# encoding: utf-8
import os

from saml2.saml import NAME_FORMAT_URI
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from ckan.common import config as ckan_config

CONFIG_PATH = os.path.dirname(__file__)
BASE = ckan_config.get('ckan.site_url')

settings = {
        'entityid': 'urn:mace:umu.se:saml:ckan:sp',
        'description': 'CKAN saml2 authorizer',
        'service': {
            'sp': {
                'name': 'CKAN SP',
                'endpoints': {
                    'assertion_consumer_service': [BASE + '/acs']
                },
                'allow_unsolicited': True,
            }
        },
        'debug': 0,
        'metadata': {
            # TODO make the location to be read from ckan config
            'local': [CONFIG_PATH + '/idp.xml'],
        },
        'contact_person': [{
            'given_name': 'John',
            'sur_name': 'Smith',
            'email_address': ['john.smith@example.com'],
            'contact_type': 'technical',
        },
        ],
        'name_form': NAME_FORMAT_URI,
        'logger': {
            'rotating': {
                'filename': '/tmp/sp.log',
                'maxBytes': 100000,
                'backupCount': 5,
            },
            'loglevel': 'error',
        }
}


def saml_client():
    sp_config = Saml2Config()
    sp_config.load(settings)
    sp_config.allow_unknown_attributes = True
    client = Saml2Client(config=sp_config)
    return client
