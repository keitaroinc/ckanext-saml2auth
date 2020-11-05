# encoding: utf-8
import string
import secrets

from ckan.common import config, asbool


def generate_password():
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(8))
    return password


def is_default_login_enabled():
    return asbool(
        config.get('ckanext.saml2auth.enable_default_login',
                   False))
