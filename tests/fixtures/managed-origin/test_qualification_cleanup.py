"""Offline synthetic-only volume disposal boundaries."""
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from deploy.local import origin21_managed_qualification_cleanup as disposal,origin21_managed_qualification as qualification

class QualificationDisposalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.base=Path(self.temp.name).resolve(); self.parent=self.base/'qualification'; self.parent.mkdir(mode=0o700); self.token='a'*32; self.folder=self.parent/self.token; self.folder.mkdir(mode=0o700)
        self.name='contour-managed-origin21-qual-'+self.token+'-data'
        containers=['%064x'%i for i in range(1,10)]; networks=['%064x'%i for i in range(10,12)]
        intent={'version':1,'kind':'synthetic','token':self.token,'volume':self.name,'head':'b'*40,'destination':qualification.DESTINATION,'destination_sha256':'c'*64,'source_identity':'source','build_image':'sha256:'+'d'*64,'build_receipt_sha256':'e'*64}
        self.write('qualification.intent',intent)
        initializer=self.base/'initializer.intent'; initializer.write_bytes(json.dumps({'version':1,'head':'b'*40,'build_image':'sha256:'+'d'*64,'build_receipt_sha256':'e'*64,'network':disposal.init.NETWORK,'volume':self.name,'token':'c'*32},sort_keys=True,separators=(',',':')).encode()); initializer.chmod(0o600)
        sha=hashlib.sha256(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.write('topology.intent',{'version':1,'token':self.token,'intent_sha256':sha,'containers':containers,'networks':networks})
        self.write('topology.cleaned',{'version':1,'token':self.token,'intent_sha256':sha,'containers_removed':containers,'networks_removed':networks})
        self.calls=[]; self.live=False; self.wrong_label=False; self.existing_id=False
    def tearDown(self): self.temp.cleanup()
    def write(self,name,value):
        path=self.folder/name; path.write_bytes(json.dumps(value,sort_keys=True,separators=(',',':')).encode()); path.chmod(0o600)
    def command(self,args,*a,**k):
        self.calls.append(args)
        if args[:3]==['docker','ps','-aq'] and args[-1].startswith('volume='): return b'live' if self.live else b''
        if args[:3]==['docker','ps','-aq'] and args[-1].startswith('id=') and self.existing_id: return b'live'
        if args[:3]==['docker','volume','rm']: return self.name.encode()
        return b''
    def run_disposal(self):
        volume={'Name':self.name,'Driver':'local','Scope':'local','Options':{},'Labels':{disposal.LABEL:'bad' if self.wrong_label else self.token,disposal.init.LABEL:'c'*32}}
        proof=object.__new__(qualification.OwnedManagedQualification); object.__setattr__(proof,'_token',self.token)
        with mock.patch.object(qualification.OwnedManagedQualification,'verify',return_value=proof),mock.patch.object(disposal.origin21_state,'MANAGED_SOURCE_FILES',(disposal.SOURCE,)),mock.patch.object(disposal.init,'BASE',self.base),mock.patch.object(disposal.init,'_source',return_value='source'),mock.patch.object(disposal.products,'_objects',return_value=volume),mock.patch.object(disposal.products,'_command',side_effect=self.command):
            disposal.dispose_synthetic_volume(proof)
    def test_only_exact_unused_synthetic_volume_removed(self):
        self.run_disposal()
        removed=[x for x in self.calls if x[:3]==['docker','volume','rm']]
        self.assertEqual(removed,[['docker','volume','rm',self.name]])
        self.assertTrue((self.folder/'volume-dispose.intent').exists()); self.assertTrue((self.folder/'volume-dispose.done').exists())
    def test_in_use_or_wrong_label_never_removes(self):
        for attr in ('live','wrong_label'):
            with self.subTest(attr=attr):
                setattr(self,attr,True)
                with self.assertRaises(ValueError): self.run_disposal()
                self.assertFalse(any(x[:3]==['docker','volume','rm'] for x in self.calls))
                setattr(self,attr,False)
    def test_surviving_recorded_container_blocks_before_volume_mutation(self):
        self.existing_id=True
        with self.assertRaises(ValueError): self.run_disposal()
        self.assertFalse(any(x[:3]==['docker','volume','rm'] for x in self.calls))
        self.assertFalse((self.folder/'volume-dispose.intent').exists())

    def test_incomplete_topology_record_blocks(self):
        self.write('topology.cleaned',{'version':1,'token':self.token,'intent_sha256':'0'*64,'containers_removed':[],'networks_removed':[]})
        with self.assertRaises(ValueError): self.run_disposal()
        self.assertFalse(self.calls)

if __name__=='__main__': unittest.main()
