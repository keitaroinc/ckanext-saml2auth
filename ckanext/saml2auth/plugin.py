"""
Copyright (c) 2020 Keitaro AB

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

# encoding: utf-8
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

from ckanext.saml2auth.views.saml2auth import saml2auth
from ckanext.saml2auth import helpers as h


class Saml2AuthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.ITemplateHelpers)

    # ITemplateHelpers

    def get_helpers(self):
        return {
            'is_default_login_enabled':
                h.is_default_login_enabled
        }

    # IConfigurable

    def configure(self, config):
        # Certain config options must exists for the plugin to work. Raise an
        # exception if they're missing.
        missing_config = "{0} is not configured. Please amend your .ini file."
        config_options = (
            'ckanext.saml2auth.user_email',
        )
        if not config.get('ckanext.saml2auth.idp_metadata.local_path'):
            config_options += ('ckanext.saml2auth.idp_metadata.remote_url',)
        for option in config_options:
            if not config.get(option, None):
                raise RuntimeError(missing_config.format(option))

        first_and_last_name = all((
            config.get('ckanext.saml2auth.user_firstname'),
            config.get('ckanext.saml2auth.user_lastname')
        ))
        full_name = config.get('ckanext.saml2auth.user_fullname')

        if not first_and_last_name and not full_name:
            raise RuntimeError('''
You need to provide both ckanext.saml2auth.user_firstname +
ckanext.saml2auth.user_lastname or ckanext.saml2auth.user_fullname'''.strip())

        acs_endpoint = config.get('ckanext.saml2auth.acs_endpoint')
        if acs_endpoint and not acs_endpoint.startswith('/'):
            raise RuntimeError('ckanext.saml2auth.acs_endpoint should start with a slash ("/")')

    # IBlueprint

    def get_blueprint(self):
        return [saml2auth]

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'saml2auth')
