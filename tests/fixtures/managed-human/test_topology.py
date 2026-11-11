import unittest
from deploy.local import origin21_managed_human_topology as topology


class TopologyTest(unittest.TestCase):
    def test_only_exact_final_eleven_and_three_memberships(self):
        ids = {name: format(i+1, '064x') for i,name in enumerate(topology.CONTAINERS)}
        networks = {
            'business': {ids[n] for n in ('replica1','replica2','destination','native-gateway','native-envoy')},
            'capture': {ids[n] for n in ('postgres','origin21-capture-ingress','origin21-capture-worker','native-gateway','app')},
            'human': {ids[n] for n in ('app','mvp-keycloak')},
        }
        topology.validate_membership(ids, networks)
        networks['capture'].add('f'*64)
        with self.assertRaises(ValueError): topology.validate_membership(ids, networks)
        networks['capture'].remove('f'*64)
        networks['human'].remove(ids['app'])
        with self.assertRaises(ValueError): topology.validate_membership(ids, networks)
        networks['human'].add(ids['app'])
        ids['app'] = ids['postgres']
        with self.assertRaises(ValueError): topology.validate_membership(ids, networks)

    def test_network_identity_and_ownership_are_checked(self):
        from deploy.local import origin21_profile as profiles
        ids = {name: format(i+1, '064x') for i,name in enumerate(topology.CONTAINERS)}
        network_ids = {'business':'a'*64, 'capture':'b'*64, 'human':'c'*64}
        names = {'business':profiles.HUMAN.network, 'capture':'apicontour-origin21-managed-human-db_default', 'human':profiles.HUMAN.project+'_human'}
        projects = {'business':profiles.HUMAN.project, 'capture':'apicontour-origin21-managed-human-db', 'human':profiles.HUMAN.project}
        members = {'business':('replica1','replica2','destination','native-gateway','native-envoy'), 'capture':('postgres','origin21-capture-ingress','origin21-capture-worker','native-gateway','app'), 'human':('app','mvp-keycloak')}
        records = {kind:{'Name':names[kind],'Id':network_ids[kind],'Internal':True,
                         'Labels':{'com.docker.compose.project':projects[kind], 'com.docker.compose.network':'human' if kind=='human' else 'default', 'org.apicontour.origin21.owner':'d'*64, 'org.apicontour.managed-db-owner':'e'*32},
                         'Containers':{ids[name]:{} for name in members[kind]}} for kind in names}
        topology.validate_networks(ids,records,network_ids,'d'*64,'e'*32)
        records['human']['Id'] = 'e'*64
        with self.assertRaises(ValueError): topology.validate_networks(ids,records,network_ids,'d'*64,'e'*32)
        records['human']['Id'] = network_ids['human']
        records['human']['Labels']['org.apicontour.origin21.owner'] = 'e'*64
        with self.assertRaises(ValueError): topology.validate_networks(ids,records,network_ids,'d'*64,'e'*32)

    def test_app_service_configuration_and_generation_are_exact(self):
        import copy
        import os
        from deploy.local import origin21_profile as profiles
        selected=profiles.HUMAN; base=selected.profile.state.parent
        cid='a'*64; token='b'*64; started='2026-01-01T00:00:00Z'
        image={'id':'sha256:'+'c'*64,'env':['PATH=/usr/bin'],'cmd':None,
               'entrypoint':['/usr/local/bin/contour-platform'],'workdir':'','user':'65534'}
        networks={'capture':'d'*64,'human':'e'*64}
        paths={'/run/config/platform.json':base/'container-platform.json','/run/config/business.json':base/'container-business.json',
               '/run/config/ca.crt':base/'ca.crt','/run/config/server.crt':base/'human/app.crt','/run/config/server.key':base/'human/app.key',
               '/run/config/jwks.json':base/'approved-jwks.json','/run/config/database-password':base/'database-password'}
        ports={'9443/tcp':[{'HostIp':'127.0.0.1','HostPort':'19443'}]}
        obj={'Id':cid,'Name':'/'+selected.project+'-app-1','Image':image['id'],
             'Config':{'Image':image['id'],'User':str(os.getuid())+':'+str(os.getgid()),'Env':image['env'],'Cmd':None,
                       'Entrypoint':image['entrypoint'],'WorkingDir':'','Labels':{'com.docker.compose.project':selected.project,
                       'com.docker.compose.service':'app','org.apicontour.origin21.owner':token}},
             'State':{'Running':True,'StartedAt':started,'Restarting':False},
             'HostConfig':{'Privileged':False,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],
                           'Memory':512*1024*1024,'NanoCpus':1000000000,'PidsLimit':128,'PortBindings':ports,
                           'PublishAllPorts':False,'RestartPolicy':{'Name':'no'},'ReadonlyRootfs':True,'Tmpfs':{'/tmp':'rw,noexec,nosuid,size=16m'}},
             'Mounts':[{'Destination':target,'Source':str(path),'Type':'bind','RW':False} for target,path in paths.items()],
             'NetworkSettings':{'Ports':ports,'Networks':{selected.project+'_human':{'NetworkID':networks['human']},
                'apicontour-origin21-managed-human-db_default':{'NetworkID':networks['capture']}}}}
        topology.validate_service(obj,'app',cid,image,token,networks,started)
        for mutate in (lambda x:x['State'].update(StartedAt='2026-01-02T00:00:00Z'),
                       lambda x:x['HostConfig']['PortBindings']['9443/tcp'][0].update(HostIp='0.0.0.0'),
                       lambda x:x['Mounts'][0].update(RW=True),
                       lambda x:x['HostConfig']['Tmpfs'].update({'/tmp':'rw,size=16m'}),
                       lambda x:x['NetworkSettings']['Networks'].update(extra={'NetworkID':'f'*64})):
            changed=copy.deepcopy(obj); mutate(changed)
            with self.assertRaises(ValueError): topology.validate_service(changed,'app',cid,image,token,networks,started)

    def test_private_intent_rejects_model_and_token_drift_before_use(self):
        import json
        from unittest.mock import patch
        from deploy.local import origin21_products as products
        token='a'*64; image='sha256:'+'b'*64
        value={'version':1,'token':token,'models':{'identity':'c'*64,'application':'d'*64},
               'images':{'app':image,'mvp-keycloak':'sha256:'+'e'*64}}
        raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        with patch('deploy.pilot.origin_credentials._file', return_value=raw), patch.object(products, '_verify_model') as verify:
            self.assertEqual(topology._verify_intent({'token':token,'app_image_id':image}), value)
            self.assertEqual(verify.call_count, 2)
        with patch('deploy.pilot.origin_credentials._file', return_value=raw), patch.object(products, '_verify_model') as verify:
            with self.assertRaises(ValueError): topology._verify_intent({'token':'f'*64,'app_image_id':image})
            verify.assert_not_called()

    def test_identity_service_rejects_extra_port_or_volume_drift(self):
        import copy
        from deploy.local import origin21_profile as profiles
        selected=profiles.HUMAN; base=selected.profile.state.parent; cid='a'*64; token='b'*64
        started='2026-01-01T00:00:00Z'; networks={'capture':'d'*64,'human':'e'*64}
        image={'id':'sha256:'+'c'*64,'env':['PATH=/usr/bin'],'cmd':None,'entrypoint':['/opt/keycloak/bin/kc.sh'],'workdir':'','user':'1000'}
        ref='quay.io/keycloak/keycloak@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244'
        ports={'8443/tcp':[{'HostIp':'127.0.0.1','HostPort':'18444'}]}
        cmd=['start','--db=dev-file','--hostname=https://idp.mvp.localhost:18444','--http-enabled=false',
             '--https-certificate-file=/run/local/idp.crt','--https-certificate-key-file=/run/local/idp.key','--import-realm']
        obj={'Id':cid,'Name':'/'+selected.project+'-mvp-keycloak-1','Image':image['id'],
             'Config':{'Image':ref,'User':'1000:1000','Env':image['env'],'Cmd':cmd,'Entrypoint':image['entrypoint'],'WorkingDir':'',
                       'Labels':{'com.docker.compose.project':selected.project,'com.docker.compose.service':'mvp-keycloak','org.apicontour.origin21.owner':token}},
             'State':{'Running':True,'StartedAt':started,'Restarting':False},
             'HostConfig':{'Privileged':False,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],'Memory':1024*1024*1024,
                           'NanoCpus':2000000000,'PidsLimit':256,'PortBindings':ports,'PublishAllPorts':False,'RestartPolicy':{'Name':'no'},'ReadonlyRootfs':False},
             'Mounts':[{'Destination':'/run/local','Source':str(base/'human/idp'),'Type':'bind','RW':False},
                       {'Destination':'/opt/keycloak/data/import','Source':str(base/'human/realm'),'Type':'bind','RW':False},
                       {'Destination':'/opt/keycloak/data','Name':selected.project+'_human-keycloak-data','Type':'volume','RW':True}],
             'NetworkSettings':{'Ports':ports,'Networks':{selected.project+'_human':{'NetworkID':networks['human'],'Aliases':['mvp-keycloak']}}}}
        topology.validate_service(obj,'mvp-keycloak',cid,image,token,networks,started)
        for mutate in (lambda x:x['HostConfig']['PortBindings'].update({'9000/tcp':[{'HostIp':'0.0.0.0','HostPort':'9000'}]}),
                       lambda x:x['Mounts'][-1].update(Name='other-volume'),lambda x:x['Config'].update(User='0')):
            changed=copy.deepcopy(obj); mutate(changed)
            with self.assertRaises(ValueError): topology.validate_service(changed,'mvp-keycloak',cid,image,token,networks,started)
