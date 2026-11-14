import unittest
from deploy.local import origin21_products as products, origin21_profile as profiles


def model():
    services = {name: {'networks': {'default': {}}} for name in products.PRODUCTS}
    services.update({name: {'networks': {'capture': {}}} for name in products.COMPANIONS})
    services['destination']['networks'] = {'default': {}}
    services['native-gateway']['networks'] = {'default': {}, 'capture': {}}
    services['native-envoy']['networks'] = {'default': {}}
    services['app'] = {'networks': {'capture': {}, 'human': {}}}
    services['mvp-keycloak'] = {'networks': {'human': {}}}
    return {'name': profiles.HUMAN.project, 'services': services,
            'networks': {'default': {}, 'capture': {}, 'human': {}},
            'volumes': {'human-keycloak-data': {}}}


class ModelTest(unittest.TestCase):
    def test_closed_human_groups_reject_extra_services_and_networks(self):
        for group, names in [('products', products.PRODUCTS), ('companions', products.COMPANIONS), ('identity', ('mvp-keycloak',)), ('application', ('app',))]:
            result = products._select_model(model(), group, selected=profiles.HUMAN)
            self.assertEqual(set(result['services']), set(names))
        value = model(); value['services']['extra'] = {'networks': {'human': {}}}
        with self.assertRaises(ValueError): products._select_model(value, 'identity', selected=profiles.HUMAN)
        value = model(); value['networks']['extra'] = {}
        with self.assertRaises(ValueError): products._select_model(value, 'identity', selected=profiles.HUMAN)

def test_identity_volume_and_context_cannot_be_redirected(self):
    value=model()
    value['services']['mvp-keycloak']['volumes']=[{'type':'volume','source':'other','target':'/opt/keycloak/data'}]
    with self.assertRaises(ValueError): products._select_model(value, 'identity', selected=profiles.HUMAN)
    with self.assertRaises(ValueError): products._select_model(model(), 'identity', selected=profiles.MANAGED)
    with self.assertRaises(ValueError): products._select_model(model(), 'identity', selected=profiles.HUMAN._replace())
