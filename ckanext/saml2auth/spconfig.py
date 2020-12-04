# encoding: utf-8
from saml2.saml import NAME_FORMAT_URI

from ckan.common import config as ckan_config
from ckan.common import asbool, aslist


def get_config():
    base = ckan_config.get('ckan.site_url')
    debug = asbool(ckan_config.get('debug'))
    allow_unknown_attributes = \
        ckan_config.get(u'ckanext.saml2auth.allow_unknown_attributes', True)
    name_id_format = \
        aslist(ckan_config.get(u'ckanext.saml2auth.sp.name_id_format',
                               "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"))
    location = \
        ckan_config.get(u'ckanext.saml2auth.idp_metadata.location')
    local_path = \
        ckan_config.get(u'ckanext.saml2auth.idp_metadata.local_path')
    remote_url = \
        ckan_config.get(u'ckanext.saml2auth.idp_metadata.remote_url')
    # Consider different name
    remote_cert = \
        ckan_config.get(u'ckanext.saml2auth.idp_metadata.remote_cert')

    config = {
        u'entityid': u'urn:mace:umu.se:saml:ckan:sp',
        u'description': u'CKAN saml2 Service Provider',
        # Set True if eg.Azure or Microsoft Idp used
        u'allow_unknown_attributes': allow_unknown_attributes,
        u'service': {
            u'sp': {
                u'name': u'CKAN SP',
                u'endpoints': {
                    u'assertion_consumer_service': [base + u'/acs']
                },
                u'allow_unsolicited': True,
                u'name_id_policy_format': name_id_format,
                u'name_id_format': name_id_format
            }
        },
        u'metadata': {},
        u'debug': 1 if debug else 0,
        u'name_form': NAME_FORMAT_URI
    }

    if location == u'local':
        config[u'metadata'][u'local'] = [local_path]
    elif location == u'remote':
        remote = [{
                u'url': remote_url,
                u'cert': remote_cert
            }]
        config[u'metadata'][u'remote'] = remote

    return config
