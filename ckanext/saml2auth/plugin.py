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
            'ckanext.saml2auth.idp_metadata.local_path',
            'ckanext.saml2auth.user_firstname',
            'ckanext.saml2auth.user_lastname',
            'ckanext.saml2auth.user_email'
        )
        for option in config_options:
            if not config.get(option, None):
                raise RuntimeError(missing_config.format(option))

    # IBlueprint

    def get_blueprint(self):
        return [saml2auth]

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'saml2auth')
