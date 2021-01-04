# encoding: utf-8
from ckan.lib.helpers import url_for
from ckan.tests.helpers import FunctionalTestBase


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
