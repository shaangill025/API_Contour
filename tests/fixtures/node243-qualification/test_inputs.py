import copy
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('node243_inputs',Path(__file__).resolve().parents[3]/'scripts/qualify-node243-layer.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class InputIdentityTests(unittest.TestCase):
    def value(self, role, arch='arm64'):
        item=m.INPUTS[role]; index=item['index']
        return {'Id':index,'Os':'linux','Architecture':arch,
                'Descriptor':{'digest':index,'mediaType':'application/vnd.oci.image.index.v1+json'},
                'RepoDigests':[item['repo']+'@'+index],
                'Config':{'Env':['NODE_VERSION='+item['version']]}}

    def test_supported_models_for_both_roles_and_platforms(self):
        for role in ('node','base'):
            for arch in ('arm64','amd64'):
                with self.subTest(role=role,arch=arch):
                    image=self.value(role,arch)
                    result=m.validate_input(image,role,arch)
                    self.assertEqual(result['model'],'containerd-index')
                    self.assertFalse(result['engine_child_config_binding_verified'])
                    image['Id']=m.EXPECTED[arch][0 if role=='node' else 1]
                    image.pop('Descriptor')
                    self.assertEqual(m.validate_input(image,role,arch)['model'],'legacy-config')

    def test_wrong_index_descriptor_platform_version_repo_and_role_rejected(self):
        for change in ('index','descriptor','media','platform','os','version','duplicate_version','repo','role','legacy_config'):
            with self.subTest(change=change):
                image=self.value('node'); role='node'
                if change=='index': image['Id']='sha256:'+'a'*64
                if change=='descriptor': image['Descriptor']['digest']='sha256:'+'a'*64
                if change=='media': image['Descriptor']['mediaType']='application/json'
                if change=='platform': image['Architecture']='amd64'
                if change=='os': image['Os']='windows'
                if change=='version': image['Config']['Env']=['NODE_VERSION=24.22.1']
                if change=='duplicate_version': image['Config']['Env'].append('NODE_VERSION=24.22.3')
                if change=='repo': image['RepoDigests']=[]
                if change=='role': role='base'
                if change=='legacy_config': image['Id']=m.EXPECTED['amd64'][0]
                with self.assertRaises((ValueError,KeyError)):
                    m.validate_input(image,role,'arm64')
