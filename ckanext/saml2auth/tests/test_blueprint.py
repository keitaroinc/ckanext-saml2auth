# encoding: utf-8
import os

from ckan.plugins.toolkit import url_for
from ckan.tests.helpers import FunctionalTestBase, change_config

here = os.path.dirname(os.path.abspath(__file__))
extras_folder = os.path.join(here, 'extras')


class TestBlueprint(FunctionalTestBase):

    def test_user_register_disabled_by_default(self):
        app = self._get_test_app()
        url = url_for(u'user.register')
        response = app.get(url=url, status=403, expect_errors=True)
        assert 403 == response.status_int

        assert u'This resource is forbidden' \
               u' by the system administrator. ' \
               u'Only SSO through SAML2 authorization ' \
               u'is available at this moment.' in response

    def test_internal_user_login_disabled_by_deafult(self):
        app = self._get_test_app()
        url = url_for(u'user.login')
        response = app.get(url=url, status=403, expect_errors=True)
        assert 403 == response.status_int

        assert u'This resource is forbidden' \
               u' by the system administrator. ' \
               u'Only SSO through SAML2 authorization ' \
               u'is available at this moment.' in response

    @change_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
    @change_config(u'ckanext.saml2auth.idp_metadata.local_path',
                   os.path.join(extras_folder, 'provider2', 'idp.xml'))
    def test_came_from_sent_as_relay_state(self):

        app = self._get_test_app()
        url = url_for('saml2auth.saml2login', came_from='/dataset/my-dataset')

        response = app.get(url=url, follow_redirects=False)
        assert 'RelayState=%2Fdataset%2Fmy-dataset' in response.headers['Location']