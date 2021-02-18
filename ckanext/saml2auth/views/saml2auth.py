# encoding: utf-8
import logging
from flask import Blueprint
from saml2 import entity
from saml2.authn_context import requested_authn_context

import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.logic as logic
import ckan.lib.dictization.model_dictize as model_dictize
from ckan.lib import base
from ckan.views.user import set_repoze_user
from ckan.common import config, g, request

from ckanext.saml2auth.spconfig import get_config as sp_config
from ckanext.saml2auth import helpers as h


log = logging.getLogger(__name__)
saml2auth = Blueprint(u'saml2auth', __name__)


def _get_requested_authn_contexts():
    requested_authn_contexts = config.get('ckanext.saml2auth.requested_authn_context',
                                          None)
    if requested_authn_contexts is None or requested_authn_contexts == '':
        return []

    return requested_authn_contexts.strip().split()


def process_user(email, saml_id, full_name):
    """ Check if CKAN-SAML user exists for the current SAML login """

    context = {
        u'ignore_auth': True,
        u'keep_email': True,
        u'model': model
    }

    saml_user = model.Session.query(model.User) \
        .filter(model.User.plugin_extras[(u'saml2auth', u'saml_id')].astext == saml_id) \
        .first()

    # First we check if there is a SAML-CKAN user
    if saml_user:
        # If account exists and is deleted, reactivate it.
        h.activate_user_if_deleted(saml_user)

        user_dict = model_dictize.user_dictize(saml_user, context)
        # Update the existing CKAN-SAML user only if
        # SAML user name or SAML user email are changed
        # in the identity provider
        if email != user_dict['email'] \
                or full_name != user_dict['fullname']:
            user_dict['email'] = email
            user_dict['fullname'] = full_name
            try:
                user_dict = logic.get_action(u'user_update')(context, user_dict)
            except logic.ValidationError as e:
                error_message = (e.error_summary or e.message or e.error_dict)
                base.abort(400, error_message)
        return user_dict['name']

    # If there is no SAML user but there is a regular CKAN
    # user with the same email as the current login,
    # make that user a SAML-CKAN user and change
    # it's pass so the user can use only SSO
    ckan_user = model.User.by_email(email)
    if ckan_user:
        # If account exists and is deleted, reactivate it.
        h.activate_user_if_deleted(ckan_user[0])

        ckan_user_dict = model_dictize.user_dictize(ckan_user[0], context)
        try:
            ckan_user_dict[u'password'] = h.generate_password()
            ckan_user_dict[u'plugin_extras'] = {
                u'saml2auth': {
                    # Store the saml username
                    # in the corresponding CKAN user
                    u'saml_id': saml_id
                }
            }
            return logic.get_action(u'user_update')(context, ckan_user_dict)[u'name']
        except logic.ValidationError as e:
            error_message = (e.error_summary or e.message or e.error_dict)
            base.abort(400, error_message)

    data_dict = {
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
    try:
        return logic.get_action(u'user_create')(context, data_dict)[u'name']
    except logic.ValidationError as e:
        error_message = (e.error_summary or e.message or e.error_dict)
        base.abort(400, error_message)


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

    g.user = process_user(email, saml_id, full_name)

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
