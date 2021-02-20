# encoding: utf-8
import os
import pytest
from ckanext.saml2auth.views.saml2auth import saml2login


here = os.path.dirname(os.path.abspath(__file__))
extras_folder = os.path.join(here, 'extras')


@pytest.mark.ckan_config(u'ckanext.saml2auth.requested_authn_context_comparison', 'bad_value')
@pytest.mark.ckan_config(u'ckanext.saml2auth.requested_authn_context', 'req1 req2')
@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.local_path',
                         os.path.join(extras_folder, 'provider0', 'idp.xml'))
@pytest.mark.usefixtures(u'with_request_context')
def test_empty_comparison():
    with pytest.raises(ValueError) as e:
        saml2login()
        assert 'Unexpected comparison' in e
