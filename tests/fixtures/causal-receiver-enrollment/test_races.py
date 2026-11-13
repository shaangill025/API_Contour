"""Offline race-construction controls; no database or services."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('receiver_races',ROOT/'scripts/receiver_enrollment_races.py')
races=importlib.util.module_from_spec(spec); spec.loader.exec_module(races)


class RaceBuilders(unittest.TestCase):
    def test_receiver_scope_and_fresh_session(self):
        t='2026-11-12T23:00:00.123456Z'
        for epoch in range(2,8):
            claim=races._session_claim(epoch,t); call=races._receiver(epoch,t,races._hex(epoch),races._hex(epoch+20))
            self.assertIn(races.RUNTIME,claim); self.assertIn(races.LIFECYCLE,claim)
            self.assertIn('contour.enroll_causal_receiver',call); self.assertIn(str(epoch)+'::numeric',call)
        self.assertNotEqual(races._session_claim(2,t),races._session_claim(3,t))
    def test_inputs_fail_closed(self):
        for when in ('x',"2026-11-12T23:00:00.123456Z';DROP TABLE x;--"):
            with self.assertRaises(ValueError): races._session_claim(2,when)
        with self.assertRaises(ValueError): races._receiver(1,'2026-11-12T23:00:00.123456Z',races._hex(1),races._hex(2))
        with self.assertRaises(ValueError): races._product(9,races._hex(1))
        with self.assertRaises(ValueError): races._classify(races.T1,'x','23505','arbitrary')
    def test_classification_uses_observed_barrier_and_exact_sqlstate(self):
        call=races._product(1,races._hex(2))
        sql=races._classify(races.T2,call,'40001','credential gate busy','gateway_product')
        for item in ('pg_stat_activity',"wait_event='advisory'",'race_winner_gateway_product',"code='40001'","msg='credential gate busy'",'UNEXPECTED_SUCCESS'):
            self.assertIn(item,sql)
        self.assertNotIn('INSERT INTO contour.causal_leaf_reservations',sql)
    def test_actor_roles_are_fixed_and_superuser_barrier_is_separate(self):
        t='2026-11-12T23:00:00.123456Z'
        receiver=races._receiver(2,t,races._hex(3),races._hex(4)); product=races._product(1,races._hex(5))
        for tenant,call,role in ((races.T1,receiver,'contour_causal_evidence_provisioner'),(races.T2,product,'contour_admin')):
            sql=races._actor(tenant,call,'SELECT 1;')
            self.assertLess(sql.index('SET LOCAL ROLE '+role),sql.index('SELECT '+call))
            self.assertLess(sql.index('SELECT '+call),sql.index('RESET ROLE'))
            contender=races._classify(tenant,call,'40001','credential gate busy','gateway_product')
            self.assertLess(contender.index('pg_stat_activity'),contender.index('SET LOCAL ROLE '+role))
            scoped=contender.split('SET LOCAL ROLE '+role,1)[1].split('RESET ROLE',1)[0]
            self.assertNotIn('pg_stat_activity',scoped); self.assertIn('PERFORM '+call,scoped)
        with self.assertRaises(ValueError): races._actor(races.T2,receiver)
        seen=[]
        races._issue(lambda sql:(seen.append(sql) or races.T1+'\n2'),2,t)
        self.assertIn('SET LOCAL ROLE contour_causal_issuer',seen[0]); self.assertIn('RESET ROLE',seen[0])

    def test_failure_cannot_return_receipt(self):
        class Existing: pass
        with self.assertRaises(ValueError): races.run_races(lambda _: 'untrusted SQL output',Existing())
        self.assertEqual(len(races.RESULTS),6)


if __name__=='__main__': unittest.main()
