import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('gateway_fixture',ROOT/'scripts/gateway_reader_fixture.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)

class FixtureTests(unittest.TestCase):
 def test_fixed_scenario_and_order(self):
  sql=[];payload=[]; n=0
  def execute(text):
   nonlocal n
   sql.append(text)
   if "SELECT json_build_object('generation'" in text:
    n+=1
    return json.dumps({'generation':str(n)*32,'metadata_sha256':'ab'*32,'expires_at':'2026-11-13T00:00:00.000000Z'})
   return ''
  result=f.run(execute=execute,probe_call=lambda raw:payload.append(json.loads(raw)),ca_pem=b'CA',port=5432,passwords={k:'ab'*32 for k in ('reader','wrong','mixed','transitive')})
  self.assertEqual(result,f.CHECKS)
  self.assertEqual([(x['mode'],x['user']) for x in payload],[('positive','gateway_reader_login'),('denied','gateway_wrong_login'),('denied','gateway_mixed_login'),('denied','gateway_transitive_login'),('unavailable','gateway_reader_login'),('positive','gateway_reader_login'),('unavailable','gateway_reader_login'),('unavailable','gateway_reader_login')])
  self.assertLess(next(i for i,x in enumerate(sql) if 'close_causal_gateway' in x),next(i for i,x in enumerate(sql) if "repeat('c4',32)" in x))
  self.assertTrue(any("SET technique='runtime'" in x for x in sql))
  self.assertTrue(any('causal_gateway_enrollments' in x and 'insufficient_privilege' in x for x in sql))
 def test_bad_credentials_rejected_before_execution(self):
  calls=[]
  with self.assertRaises(ValueError): f.run(execute=lambda x:calls.append(x),probe_call=lambda x:None,ca_pem=b'CA',port=5432,passwords={'reader':'bad'})
  self.assertEqual(calls,[])
if __name__=='__main__': unittest.main()
