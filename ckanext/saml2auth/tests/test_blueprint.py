# encoding: utf-8
import pytest

from ckan.lib.helpers import url_for


@pytest.mark.usefixtures(u'clean_db', u'clean_index')
@pytest.mark.ckan_config(u'ckan.plugins', u'saml2auth')
class TestBlueprint(object):

    def test_user_register_disabled_by_default(self, app):
        url = url_for(u'user.register')
        response = app.get(url=url)
        assert 403 == response.status_code

        assert u'This resource is forbidden' \
               u' by the system administrator. ' \
               u'Only SSO through SAML2 authorization ' \
               u'is available at this moment.' in response

    def test_internal_user_login_disabled_by_deafult(self, app):
        url = url_for(u'user.login')
        response = app.get(url=url)
        assert 403 == response.status_code

        assert u'This resource is forbidden' \
               u' by the system administrator. ' \
               u'Only SSO through SAML2 authorization ' \
               u'is available at this moment.' in response

    # TODO write tests will all different config variations and test ACS service with mock IDP
    # @pytest.mark.ckan_config(u'ckanext.saml2auth.enable_ckan_internal_login', 'true')
    # def test_user_register_enabled(self, monkeypatch, make_app, ckan_config):
    #     monkeypatch.setitem(ckan_config, u'ckanext.saml2auth.enable_ckan_internal_login', True)
    #     url = url_for("user.register")
    #     app = make_app()
    #     response = app.get(url=url)
    #     assert 200 == response.status_code

    # def test_saml2_login(self, app):
    #     url = url_for("saml2auth.saml2login")
    #     response = app.get(url=url)
    #     assert 302 == response.status_code
