import os
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.logic as logic
import ckan.lib.dictization.model_dictize as model_dictize
from ckan.views.user import set_repoze_user
from ckan.logic.action.create import _get_random_username_from_email

from ckan.common import _, c, g, request

from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity
)
from saml2.saml import NAME_FORMAT_URI
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from ckanext.saml2auth.views.saml2acs import saml2acs

CONFIG_PATH = os.path.dirname(__file__)

BASE = 'http://localhost:5000/'

#TODO move into separate config file
def saml_client():

    settings = {
        'entityid': 'urn:mace:umu.se:saml:ckan:sp',
        'description': 'CKAN saml2 authorizer',
        'service': {
            'sp': {
                'name': 'CKAN SP',
                'endpoints': {
                    'assertion_consumer_service': [BASE + 'acs'],
                    'single_logout_service': [(BASE + 'slo',
                                               BINDING_HTTP_REDIRECT)],
                },
                'required_attributes': [
                    'uid',
                    'name',
                    'mail',
                    'status',
                    'field_display_name',
                    'realname',
                    'field_unique_id',
                ],
                'allow_unsolicited': True,
                'optional_attributes': [],
                'idp': ['urn:mace:umu.se:saml:ckan:idp'],
            }
        },
        'debug': 0,
        'metadata': {
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
    spConfig = Saml2Config()
    spConfig.load(settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client


class Saml2AuthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IBlueprint)

    def get_blueprint(self):
        return [saml2acs]

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic',
            'saml2auth')

    def identify(self):
        u'''Called to identify the user.

        If the user is identified then it should set:

         - g.user: The name of the user
         - g.userobj: The actual user object
        '''

        g.user = None
        g.userobj = None

        if request.form.get('SAMLResponse', None):
            client = saml_client()
            auth_response = client.parse_authn_request_response(
                request.form.get('SAMLResponse', None),
                entity.BINDING_HTTP_POST)
            auth_response.get_identity()
            user_info = auth_response.get_subject()

            context = {
                u'ignore_auth': True,
                u'model': model
            }
            data_dict = {
                'name': _get_random_username_from_email(user_info.text),
                'fullname': auth_response.ava['name'][0] + ' ' + auth_response.ava['lastname'][0],
                'email': auth_response.ava['email'][0],
                # TODO generate strong password
                'password': 'somestrongpass'
            }

            user = model.User.by_email(auth_response.ava['email'][0])
            if not user:
                g.user = logic.get_action(u'user_create')(context, data_dict)['name']
            else:
                model_dictize.user_dictize(user[0], context)
                data_dict['id'] = user[0].id
                data_dict['name'] = user[0].name
                g.user = logic.get_action(u'user_update')(context, data_dict)['name']
            print('----------------------------------------------g.user', g.user)
            g.userobj = model.User.by_name(g.user)
            resp = toolkit.redirect_to(u'user.me')
            set_repoze_user(data_dict[u'name'], resp)
            return resp

    def login(self):
        u'''Called before the login starts (that is before asking the user for
        user name and a password in the default authentication).
        '''
        client = saml_client()
        reqid, info = client.prepare_for_authenticate()

        redirect_url = None
        for key, value in info['headers']:
            if key is 'Location':
                redirect_url = value
        return toolkit.redirect_to(redirect_url)

    def logout(self):
        u'''Called before the logout starts (that is before clicking the logout
        button in the default authentication).
        '''

    def abort(self, status_code, detail, headers, comment):
        u'''Called on abort.  This allows aborts due to authorization issues
        to be overridden'''
        return (status_code, detail, headers, comment)
