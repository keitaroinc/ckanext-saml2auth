# encoding: utf-8
import pytest

from ckanext.saml2auth.spconfig import get_config


@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.local_path', '/path/to/idp.xml')
def test_read_metadata_local_config():
    assert get_config()[u'metadata'][u'local'] == ['/path/to/idp.xml']


@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.location', u'remote')
def test_read_metadata_remote_config():
    with pytest.raises(KeyError):
        assert get_config()[u'metadata'][u'local']

    assert get_config()[u'metadata'][u'remote']


@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.location', u'remote')
@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.remote_url', u'https://metadata.com')
@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.remote_cert', u'/path/to/local.cert')
def test_read_metadata_remote_url():
    with pytest.raises(KeyError):
        assert get_config()[u'metadata'][u'local']

    remote = get_config()[u'metadata'][u'remote'][0]
    assert remote[u'url'] == u'https://metadata.com'
    assert remote[u'cert'] == u'/path/to/local.cert'


@pytest.mark.ckan_config(u'ckanext.saml2auth.issuer', u'some:issuer')
def test_read_issuer():

    issuer = get_config()[u'entityid']
    assert issuer == u'some:issuer'
