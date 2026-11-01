"""Static structure checks; do not start a listener or Docker."""
import json
from pathlib import Path
import unittest

HERE=Path(__file__).parent

class PilotConfig(unittest.TestCase):
    def test_closed_flow_and_tls(self):
        nodes=json.loads((HERE/'flows.json').read_text())
        by_id={node['id']:node for node in nodes}
        self.assertEqual(len(by_id),len(nodes))
        tls=by_id['pilot-tls']; request=by_id['pilot-request']
        self.assertEqual(tls['certType'],'files')
        self.assertTrue(tls['verifyservercert'])
        self.assertEqual((tls['cert'],tls['key'],tls['ca']),('/pilot/tls/client.crt','/pilot/tls/client.key','/pilot/ca.crt'))
        self.assertEqual((request['method'],request['url'],request['tls']),('POST','${PILOT_TARGET}','pilot-tls'))
        self.assertTrue(request['senderr'])
        self.assertEqual(by_id['pilot-in']['wires'],[['pilot-fixed']])
        self.assertEqual(by_id['pilot-fixed']['wires'],[['pilot-request']])
        self.assertEqual(by_id['pilot-catch']['scope'],['pilot-request'])
        self.assertFalse(any(node['type']=='debug' for node in nodes))
    def test_redirect_guard_and_closed_tls_negative_variants(self):
        baseline=json.loads((HERE/'flows.json').read_text())
        base={n['id']:n for n in baseline}
        self.assertIn({'t':'set','p':'followRedirects','pt':'msg','to':'false','tot':'bool'},base['pilot-fixed']['rules'])
        for mode,field,value in [('wrong-name','servername','wrong.invalid'),('wrong-ca','ca','/pilot/tls/server.crt')]:
            variant=json.loads((HERE/('flows-'+mode+'.json')).read_text())
            by_id={n['id']:n for n in variant}
            self.assertEqual(by_id['pilot-tls'][field],value)
            self.assertTrue(by_id['pilot-tls']['verifyservercert'])
            by_id['pilot-tls'][field]=base['pilot-tls'][field]
            self.assertEqual(by_id,base)

    def test_isolated_key_mounts_and_disabled_admin(self):
        compose=(HERE/'compose.yaml').read_text()
        settings=(HERE/'settings.js').read_text()
        self.assertIn('httpAdminRoot: false',settings)
        self.assertIn('verifyservercert', (HERE/'flows.json').read_text())
        self.assertNotIn('.local-mvp/ca.key',compose)
        for replica in ('replica1','replica2'):
            for credential in ('client.key','client.crt','server.key','server.crt'):
                self.assertIn('/'+replica+'/'+credential+':/pilot/tls/'+credential+':ro',compose)
        self.assertNotIn('ports:',compose)
        self.assertIn('internal: true',compose)

if __name__=='__main__': unittest.main()
