# encoding: utf-8
from flask import Blueprint
from saml2 import entity

import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.logic as logic
import ckan.lib.dictization.model_dictize as model_dictize
from ckan.lib import base
from ckan.views.user import set_repoze_user
from ckan.logic.action.create import _get_random_username_from_email
from ckan.common import _, config, g, request, asbool

from ckanext.saml2auth.spconfig import saml_client
from ckanext.saml2auth import helpers as h


saml2auth = Blueprint(u'saml2auth', __name__)


def acs():
    u'''The location where the SAML assertion is sent with a HTTP POST.
    This is often referred to as the SAML Assertion Consumer Service (ACS) URL.
    '''
    g.user = None
    g.userobj = None

    context = {
        u'ignore_auth': True,
        u'model': model
    }

    saml_user_firstname = \
        config.get(u'ckanext.saml2auth.user_firstname')
    saml_user_lastname = \
        config.get(u'ckanext.saml2auth.user_lastname')
    saml_user_email = \
        config.get(u'ckanext.saml2auth.user_email')

    client = saml_client()
    auth_response = client.parse_authn_request_response(
        request.form.get(u'SAMLResponse', None),
        entity.BINDING_HTTP_POST)
    auth_response.get_identity()
    user_info = auth_response.get_subject()

    # SAML username - unique
    saml_id = user_info.text
    # Required user attributes for user creation
    email = auth_response.ava[saml_user_email][0]
    firstname = auth_response.ava[saml_user_firstname][0]
    lastname = auth_response.ava[saml_user_lastname][0]

    # Check if CKAN user exists for the current SAML login
    user = model.Session.query(model.User) \
        .filter(model.User.plugin_extras[(u'saml2auth', u'saml_id')].astext == saml_id) \
        .first()

    if not user:
        data_dict = {u'name': _get_random_username_from_email(email),
                     u'fullname': u'{0} {1}'.format(firstname, lastname),
                     u'email': email,
                     u'password': h.generate_password(),
                     u'plugin_extras': {
                         u'saml2auth': {
                             # Store the saml username
                             # in the corresponding CKAN user
                             u'saml_id': saml_id
                         }
                     }}
        g.user = logic.get_action(u'user_create')(context, data_dict)[u'name']
    else:
        model_dictize.user_dictize(user, context)
        # Update the existing CKAN user only if
        # SAML user name or SAML user email are changed
        # in the identity provider
        if email != user.email \
                or firstname != user.fullname.split(' ')[0] \
                or lastname != user.fullname.split(' ')[1]:
            data_dict = {u'id': user.id,
                         u'fullname': u'{0} {1}'.format(firstname, lastname),
                         u'email': email
                         }
            logic.get_action(u'user_update')(context, data_dict)
        g.user = user.name

    g.userobj = model.User.by_name(g.user)
    # log the user in programmatically
    resp = toolkit.redirect_to(u'user.me')
    set_repoze_user(g.user, resp)
    return resp


def saml2login():
    u'''Redirects the user to the
     configured identity provider for authentication
    '''
    client = saml_client()
    reqid, info = client.prepare_for_authenticate()

    redirect_url = None
    for key, value in info[u'headers']:
        if key is u'Location':
            redirect_url = value
    return toolkit.redirect_to(redirect_url)


def disable_default_login_register():
    u'''View function used to
    override and disable default Register/Login routes
    '''
    extra_vars = {u'code': [403], u'content': u'This resource is forbidden '
                                              u'by the system administrator.'}
    return base.render(u'error_document_template.html', extra_vars), 403


saml2auth.add_url_rule(u'/acs', view_func=acs, methods=[u'GET', u'POST'])
saml2auth.add_url_rule(u'/user/saml2login', view_func=saml2login)
if not h.is_default_login_enabled():
    saml2auth.add_url_rule(
        u'/user/login', view_func=disable_default_login_register)
    saml2auth.add_url_rule(
        u'/user/register', view_func=disable_default_login_register)
