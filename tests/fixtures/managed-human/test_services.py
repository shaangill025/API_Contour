import unittest
from unittest.mock import patch
from deploy.local import origin21_managed_human_services as services


class ServicesTest(unittest.TestCase):
    def test_untrusted_transport_rejected_before_preflight_or_docker(self):
        with patch.object(services.preflight, 'check') as preflight, patch.object(services.products, '_command') as command:
            with self.assertRaises(ValueError): services.start((b'a'*32,b'b'*32), object())
            preflight.assert_not_called()
            command.assert_not_called()

    def test_fixed_service_start_orders_identity_before_app_and_checks_capture(self):
        from contextlib import ExitStack
        from types import SimpleNamespace
        from deploy.local import origin21_profile as profiles, origin21_transport as transport
        selected=profiles.HUMAN; token='a'*64; capture='b'*64; human='c'*64; business='d'*64
        keycloak='e'*64; app='f'*64; image='sha256:'+'1'*64; node='sha256:'+'2'*64
        intent={'token':token,'deployment':{'id':capture,'name':'fixed-capture'},'app_image_id':image}
        seven=[format(i,'064x') for i in range(1,8)]
        baseline=({'products':[{'container_id':seven[0]},{'container_id':seven[1]}],
                   'companions':{str(i):{'id':seven[i+2]} for i in range(5)}},'envoy')
        owner=SimpleNamespace(peer=SimpleNamespace(network_id=business), publisher=object(), closed=False,
                              _load=lambda:{}, _managed_gate=lambda _:None)
        class OwnerContext:
            def __enter__(self): return owner
            def __exit__(self,*args): return False
        handle=transport.ManagedTransport(transport._MANAGED_SEAL,object(),{},'','','','',selected=selected)
        events=[]
        def command(args,*a,**kw):
            if args[1:3] in (['network','ls'],['volume','ls']): return b''
            if args[1:3]==['compose','--project-name']: return b''
            if args[1:4]==['ps','-aq','--no-trunc']:
                if 'label=com.docker.compose.service=mvp-keycloak' in args: return keycloak.encode()
                if 'label=com.docker.compose.service=app' in args: return app.encode()
                return (' '.join(seven+[keycloak])).encode()
            if args[1]=='start': events.append('start-idp' if args[2]==keycloak else 'start-app'); return args[2].encode()
            raise AssertionError(args)
        def objects(args):
            if args[1:3]==['network','inspect']:
                return {'Id':human,'Name':selected.project+'_human','Internal':True,'Containers':{},'Labels':{'com.docker.compose.project':selected.project,'com.docker.compose.network':'human','org.apicontour.origin21.owner':token}}
            if args[1:3]==['volume','inspect']:
                return {'Name':selected.project+'_human-keycloak-data','Driver':'local','Scope':'local','Labels':{'org.apicontour.origin21.owner':token,'com.docker.compose.project':selected.project,'com.docker.compose.volume':'human-keycloak-data'}}
            if args[1]=='inspect': return {'State':{'StartedAt':'2026-01-01T00:00:00Z'}}
            raise AssertionError(args)
        def image_info(ref): return {'id':node if ref.startswith('quay.io/') else image}
        def prepare(_): events.append('provision')
        def ready(): events.append('ready')
        with ExitStack() as stack:
            def mock(obj,name,**kwargs): return stack.enter_context(patch.object(obj,name,**kwargs))
            mock(services.preflight,'check')
            mock(transport.ManagedTransport,'verify')
            mock(services.origin21_ready,'check',return_value={'product_tls_and_catalog_verified':True,'ui_verified':False})
            mock(services.controller,'verify_recorded_topology')
            mock(services.products,'_read_record',return_value=intent)
            mock(services.os.path,'lexists',return_value=False)
            mock(services.products,'_command',side_effect=command)
            mock(services.products,'_objects',side_effect=objects)
            mock(services.products,'_derive_model',return_value=b'{}')
            mock(services.origin_credentials,'_write')
            mock(services,'_record')
            mock(services.products,'_verify_model',return_value='/fixed/model')
            mock(services,'_image',side_effect=image_info)
            mock(services.controller,'open_edge',return_value=OwnerContext())
            mock(services.controller,'_topology_snapshot',return_value=baseline)
            mock(services.controller,'_context_for_publisher',return_value=selected)
            mock(services.topology,'validate_service')
            mock(services,'_transition')
            mock(services.business,'prepare',side_effect=prepare)
            mock(services,'_ready',side_effect=ready)
            result=services.start((b'x'*32,b'y'*32),handle)
        self.assertEqual(events,['start-idp','provision','start-app','ready'])
        self.assertEqual(result,{'product_tls_and_catalog_verified':True,'app_tls_ready':True,'ui_verified':False})
