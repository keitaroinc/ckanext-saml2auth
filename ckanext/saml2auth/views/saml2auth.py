# encoding: utf-8
import logging
import copy

from flask import Blueprint
from saml2 import entity
from saml2.authn_context import requested_authn_context

import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.plugins as plugins
import ckan.lib.dictization.model_dictize as model_dictize
from ckan.lib import base
from ckan.views.user import set_repoze_user
from ckan.common import config, g, request

from ckanext.saml2auth.spconfig import get_config as sp_config
from ckanext.saml2auth import helpers as h
from ckanext.saml2auth.interfaces import ISaml2Auth


log = logging.getLogger(__name__)
saml2auth = Blueprint(u'saml2auth', __name__)


def _get_requested_authn_contexts():
    requested_authn_contexts = config.get('ckanext.saml2auth.requested_authn_context',
                                          None)
    if requested_authn_contexts is None or requested_authn_contexts == '':
        return []

    return requested_authn_contexts.strip().split()


def _dictize_user(user_obj):
    context = {
        u'keep_email': True,
        u'model': model,
    }
    user_dict = model_dictize.user_dictize(user_obj, context)
    # Make sure plugin_extras are included or plugins might drop the saml_id one
    # Make a copy so SQLAlchemy can track changes properly
    user_dict['plugin_extras'] = copy.deepcopy(user_obj.plugin_extras)

    return user_dict


def _get_user_by_saml_id(saml_id):
    user_obj = model.Session.query(model.User) \
        .filter(model.User.plugin_extras[(u'saml2auth', u'saml_id')].astext == saml_id) \
        .first()

    h.activate_user_if_deleted(user_obj)

    return _dictize_user(user_obj) if user_obj else None


def _get_user_by_email(email):

    user_obj = model.User.by_email(email)
    if user_obj:
        user_obj = user_obj[0]

    h.activate_user_if_deleted(user_obj)

    return _dictize_user(user_obj) if user_obj else None


def _update_user(user_dict):
    context = {
        u'ignore_auth': True,
    }

    try:
        return toolkit.get_action(u'user_update')(context, user_dict)
    except toolkit.ValidationError as e:
        error_message = (e.error_summary or e.message or e.error_dict)
        base.abort(400, error_message)


def _create_user(user_dict):
    context = {
        u'ignore_auth': True,
    }

    try:
        return toolkit.get_action(u'user_create')(context, user_dict)
    except toolkit.ValidationError as e:
        error_message = (e.error_summary or e.message or e.error_dict)
        base.abort(400, error_message)


def process_user(email, saml_id, full_name, saml_attributes):
    u'''
    Check if a CKAN-SAML user exists for the current SAML login, if not create
    a new one

    Here are the checks performed in order:

    1. Is there an existing user that matches the provided saml_id (in plugin_extras)?
    2. Is there an existing user that matches the provided email?
    3. If no CKAN user found, create a new one with the provided saml id

    Returns the user name
    '''

    user_dict = _get_user_by_saml_id(saml_id)

    # First we check if there is a SAML-CKAN user
    if user_dict:

        current_user_dict = copy.deepcopy(user_dict)

        if email != user_dict['email'] or full_name != user_dict['fullname']:
            user_dict['email'] = email
            user_dict['fullname'] = full_name

        for plugin in plugins.PluginImplementations(ISaml2Auth):
            plugin.before_saml2_user_update(user_dict, saml_attributes)

        # Update the existing CKAN-SAML user only if the SAML user name or
        # email are changed in the IdP, or if another plugin modified the
        # user dict
        if current_user_dict != user_dict:

            user_dict = _update_user(user_dict)

        return user_dict['name']

    # If there is no SAML user but there is a regular CKAN
    # user with the same email as the current login,
    # make that user a SAML-CKAN user and change
    # its password so the user can use only SSO

    user_dict = _get_user_by_email(email)

    if user_dict:
        user_dict[u'password'] = h.generate_password()
        user_dict[u'plugin_extras'] = {
            u'saml2auth': {
                # Store the saml username
                # in the corresponding CKAN user
                u'saml_id': saml_id
            }
        }

        for plugin in plugins.PluginImplementations(ISaml2Auth):
            plugin.before_saml2_user_update(user_dict, saml_attributes)

        user_dict = _update_user(user_dict)

        return user_dict['name']

    # This is the first time this SAML user has logged in, let's create a CKAN user
    # for them

    user_dict = {
        u'name': h.ensure_unique_username_from_email(email),
        u'fullname': full_name,
        u'email': email,
        u'password': h.generate_password(),
        u'plugin_extras': {
            u'saml2auth': {
                # Store the saml username
                # in the corresponding CKAN user
                u'saml_id': saml_id
            }
        }
    }

    for plugin in plugins.PluginImplementations(ISaml2Auth):
        plugin.before_saml2_user_create(user_dict, saml_attributes)

    user_dict = _create_user(user_dict)
    return user_dict[u'name']


def acs():
    u'''The location where the SAML assertion is sent with a HTTP POST.
    This is often referred to as the SAML Assertion Consumer Service (ACS) URL.
    '''
    g.user = None
    g.userobj = None

    saml_user_firstname = \
        config.get(u'ckanext.saml2auth.user_firstname')
    saml_user_lastname = \
        config.get(u'ckanext.saml2auth.user_lastname')
    saml_user_fullname = \
        config.get(u'ckanext.saml2auth.user_fullname')
    saml_user_email = \
        config.get(u'ckanext.saml2auth.user_email')

    client = h.saml_client(sp_config())
    saml_response = request.form.get(u'SAMLResponse', None)

    error = None
    try:
        auth_response = client.parse_authn_request_response(
            saml_response,
            entity.BINDING_HTTP_POST)
    except Exception as e:
        error = 'Bad login request: {}'.format(e)
    else:
        if auth_response is None:
            error = 'Empty login request'

    if error is not None:
        log.error(error)
        extra_vars = {u'code': [400], u'content': error}
        return base.render(u'error_document_template.html', extra_vars), 400

    auth_response.get_identity()
    user_info = auth_response.get_subject()

    # SAML username - unique
    saml_id = user_info.text
    # Required user attributes for user creation
    email = auth_response.ava[saml_user_email][0]

    if saml_user_firstname and saml_user_lastname:
        first_name = auth_response.ava.get(saml_user_firstname, [email.split('@')[0]])[0]
        last_name = auth_response.ava.get(saml_user_lastname, [email.split('@')[1]])[0]
        full_name = u'{} {}'.format(first_name, last_name)
    else:
        if saml_user_fullname in auth_response.ava:
            full_name = auth_response.ava[saml_user_fullname][0]
        else:
            full_name = u'{} {}'.format(email.split('@')[0], email.split('@')[1])

    g.user = process_user(email, saml_id, full_name, auth_response.ava)

    # Check if the authenticated user email is in given list of emails
    # and make that user sysadmin and opposite
    h.update_user_sysadmin_status(g.user, email)

    g.userobj = model.User.by_name(g.user)

    relay_state = request.form.get('RelayState')
    redirect_target = toolkit.url_for(
        relay_state, _external=True) if relay_state else u'user.me'

    resp = toolkit.redirect_to(redirect_target)

    # log the user in programmatically
    set_repoze_user(g.user, resp)

    for plugin in plugins.PluginImplementations(ISaml2Auth):
        resp = plugin.after_saml2_login(resp, auth_response.ava)

    return resp


def saml2login():
    u'''Redirects the user to the
     configured identity provider for authentication
    '''
    client = h.saml_client(sp_config())
    requested_authn_contexts = _get_requested_authn_contexts()
    relay_state = toolkit.request.args.get('came_from', '')

    if len(requested_authn_contexts) > 0:
        comparison = config.get('ckanext.saml2auth.requested_authn_context_comparison',
                                'minimum')
        if comparison not in ['exact', 'minimum', 'maximum', 'better']:
            error = 'Unexpected comparison value {}'.format(comparison)
            raise ValueError(error)

        final_context = requested_authn_context(
            class_ref=requested_authn_contexts,
            comparison=comparison
        )

        reqid, info = client.prepare_for_authenticate(requested_authn_context=final_context, relay_state=relay_state)
    else:
        reqid, info = client.prepare_for_authenticate(relay_state=relay_state)

    redirect_url = None
    for key, value in info[u'headers']:
        if key == u'Location':
            redirect_url = value
    return toolkit.redirect_to(redirect_url)


def disable_default_login_register():
    u'''View function used to
    override and disable default Register/Login routes
    '''
    extra_vars = {u'code': [403], u'content': u'This resource is forbidden '
                                              u'by the system administrator. '
                                              u'Only SSO through SAML2 authorization'
                                              u' is available at this moment.'}
    return base.render(u'error_document_template.html', extra_vars), 403


acs_endpoint = config.get('ckanext.saml2auth.acs_endpoint', '/acs')
saml2auth.add_url_rule(acs_endpoint, view_func=acs, methods=[u'GET', u'POST'])
saml2auth.add_url_rule(u'/user/saml2login', view_func=saml2login)
if not h.is_default_login_enabled():
    saml2auth.add_url_rule(
        u'/user/login', view_func=disable_default_login_register)
    saml2auth.add_url_rule(
        u'/user/register', view_func=disable_default_login_register)
