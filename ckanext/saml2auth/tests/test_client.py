# encoding: utf-8
import os
import pytest
from ckan.tests.helpers import change_config, _get_test_app
from ckanext.saml2auth.views.saml2auth import saml2login


here = os.path.dirname(os.path.abspath(__file__))
extras_folder = os.path.join(here, 'extras')


@change_config(u'ckanext.saml2auth.requested_authn_context_comparison', 'bad_value')
@change_config(u'ckanext.saml2auth.requested_authn_context', 'req1 req2')
@change_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
@change_config(u'ckanext.saml2auth.idp_metadata.local_path', os.path.join(extras_folder, 'provider0', 'idp.xml'))
def test_empty_comparison():
    app = _get_test_app()

    with app.flask_app.test_request_context():
        with pytest.raises(ValueError) as e:
            saml2login()
            assert 'Unexpected comparison' in e
