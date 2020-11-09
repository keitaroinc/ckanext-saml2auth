# encoding: utf-8
import os

from saml2.saml import NAME_FORMAT_URI
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from ckan.common import config as ckan_config
from ckan.common import asbool, aslist

BASE = ckan_config.get('ckan.site_url')

DEBUG = asbool(ckan_config.get('debug'))

ALLOW_UNKNOWN_ATTRIBUTES = \
    ckan_config.get(u'ckanext.saml2auth.allow_unknown_attributes', False)

NAME_ID_FORMAT = \
    aslist(ckan_config.get(u'ckanext.saml2auth.sp.name_id_format',
                           "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"))
METADATA_LOCATION = \
    ckan_config.get(u'ckanext.saml2auth.idp_metadata.location')

METADATA_LOCAL_PATH = \
    ckan_config.get(u'ckanext.saml2auth.idp_metadata.local_path')

METADATA_REMOTE_URL = \
    ckan_config.get(u'ckanext.saml2auth.idp_metadata.remote_url')

# Consider different name
METADATA_REMOTE_CERT = \
    ckan_config.get(u'ckanext.saml2auth.idp_metadata.remote_cert')


settings = {
    u'entityid': u'urn:mace:umu.se:saml:ckan:sp',
    u'description': u'CKAN saml2 Service Provider',
    # Set True if eg.Azure or Microsoft Idp used
    u'allow_unknown_attributes': ALLOW_UNKNOWN_ATTRIBUTES,
    u'service': {
        u'sp': {
            u'name': u'CKAN SP',
            u'endpoints': {
                u'assertion_consumer_service': [BASE + u'/acs']
            },
            u'allow_unsolicited': True,
            u"name_id_policy_format": NAME_ID_FORMAT,
            u"name_id_format": NAME_ID_FORMAT,
        }
    },
    u'metadata': {},
    u'debug': 1 if DEBUG else 0,
    u'name_form': NAME_FORMAT_URI
}

if METADATA_LOCATION == u'local':
    settings[u'metadata'][u'local'] = [METADATA_LOCAL_PATH]
elif METADATA_LOCATION == u'remote':
    remote = [{
            u'url': METADATA_REMOTE_URL,
            u'cert': METADATA_REMOTE_CERT
        }]
    settings[u'metadata'][u'remote'] = remote


def saml_client():
    sp_config = Saml2Config()
    sp_config.load(settings)
    sp_config.allow_unknown_attributes = True
    client = Saml2Client(config=sp_config)
    return client
