import pytest
from ckanext.saml2auth.plugin import _perform_slo
from unittest import mock
import os

here = os.path.dirname(os.path.abspath(__file__))
extras_folder = os.path.join(here, 'extras')
responses_folder = os.path.join(here, 'responses')


@pytest.mark.ckan_config(u'ckanext.saml2auth.logout_expected_binding', 'skip-external-logout')
def test_skip_external_logout():

    response = _perform_slo()

    assert response is None


@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.local_path', os.path.join(extras_folder, 'provider0', 'idp.xml'))
def test_perform_slo_no_subject_id():
    # Mock session
    with mock.patch('ckanext.saml2auth.plugin.session', {}), \
         mock.patch('ckanext.saml2auth.plugin.g', mock.Mock(user='test_user')), \
         mock.patch('ckanext.saml2auth.plugin.get_subject_id', return_value=None):
        
        response = _perform_slo()

        assert response is None