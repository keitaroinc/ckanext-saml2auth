# encoding: utf-8
import pytest

from ckanext.saml2auth.spconfig import config


@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.local_path', '/path/to/idp.xml')
def test_read_metadata_local_config():
    assert config[u'metadata'][u'local'] == ['/path/to/idp.xml']


