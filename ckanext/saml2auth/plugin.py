# encoding: utf-8
import logging

from saml2 import entity

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.logic as logic
import ckan.lib.dictization.model_dictize as model_dictize
from ckan.views.user import set_repoze_user
from ckan.logic.action.create import _get_random_username_from_email
from ckan.common import _, config, g, request

from ckanext.saml2auth.views.saml2acs import saml2acs
from ckanext.saml2auth.spconfig import saml_client
from ckanext.saml2auth.helpers import generate_password

log = logging.getLogger(__name__)


class Saml2AuthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IConfigurable)

    # IConfigurable

    def configure(self, config):
        # Certain config options must exists for the plugin to work. Raise an
        # exception if they're missing.
        missing_config = "{0} is not configured. Please amend your .ini file."
        config_options = (
            'ckanext.saml2auth.user_firstname',
            'ckanext.saml2auth.user_lastname',
            'ckanext.saml2auth.user_email'
        )
        for option in config_options:
            if not config.get(option, None):
                raise RuntimeError(missing_config.format(option))

        self.firstname = config.get('ckanext.saml2auth.user_firstname')
        self.lastname = config.get('ckanext.saml2auth.user_lastname')
        self.email = config.get('ckanext.saml2auth.user_email')


    # IBlueprint

    def get_blueprint(self):
        return [saml2acs]

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic',
            'saml2auth')

    # IAuthenticator

    def identify(self):
        u'''Called to identify the user.

        If the user is identified then it should set:

         - g.user: The name of the user
         - g.userobj: The actual user object
        '''

        g.user = None
        g.userobj = None

        # Check for user identification only if there is a SAML
        # response which means only when SAML login is initiated
        if request.form.get('SAMLResponse', None):

            context = {
                u'ignore_auth': True,
                u'model': model
            }

            client = saml_client()
            auth_response = client.parse_authn_request_response(
                request.form.get('SAMLResponse', None),
                entity.BINDING_HTTP_POST)
            auth_response.get_identity()
            user_info = auth_response.get_subject()

            # SAML username - unique
            saml_id = user_info.text
            # Required user attributes for user creation
            email = auth_response.ava[self.email][0]
            firstname = auth_response.ava[self.firstname][0]
            lastname = auth_response.ava[self.lastname][0]

            # Check if CKAN user exists for the current SAML login
            user = model.Session.query(model.User)\
                .filter(model.User.plugin_extras[('saml2auth', 'saml_id')].astext == saml_id)\
                .first()

            if not user:

                data_dict = {'name': _get_random_username_from_email(email),
                             'fullname': '{0} {1}'.format(firstname, lastname),
                             'email': email,
                             'password': generate_password(),
                             'plugin_extras': {
                                 'saml2auth': {
                                     # Store the saml username
                                     # in the corresponding CKAN user
                                     'saml_id': saml_id
                                 }
                             }}
                g.user = logic.get_action(u'user_create')(context, data_dict)['name']

            else:

                model_dictize.user_dictize(user, context)
                # Update the existing CKAN user only if
                # SAML user name or SAML user email are changed
                # in the identity provider
                if email != user.email \
                        or firstname != user.fullname.split(' ')[0] \
                        or lastname != user.fullname.split(' ')[1]:

                    data_dict = {'id': user.id,
                                 'fullname': '{0} {1}'.format(firstname, lastname),
                                 'email': email
                                 }
                    logic.get_action(u'user_update')(context, data_dict)
                g.user = user.name

            # Guess we don't need to set g.userobj because
            # CKAN will set it if it's missing in the original identify_user() function
            # g.userobj = model.User.by_name(g.user)

            # log the user in programmatically
            resp = toolkit.redirect_to(u'user.me')
            set_repoze_user(g.user, resp)
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
