# encoding: utf-8
import logging
from flask import Blueprint
from saml2 import BINDING_HTTP_POST
from saml2.authn_context import requested_authn_context

import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.logic as logic
import ckan.lib.dictization.model_dictize as model_dictize
from ckan.lib import base
from ckan.views.user import set_repoze_user
from ckan.logic.action.create import _get_random_username_from_email
from ckan.common import config, g, request

from ckanext.saml2auth.spconfig import get_config as sp_config
from ckanext.saml2auth import helpers as h


saml2auth = Blueprint(u'saml2auth', __name__)
log = logging.getLogger(__name__)


def get_ckan_user(email):
    """ Look for a CKAN user with given email.
        Activate the user if it's deleted
        """
    ckan_users = model.User.by_email(email)
    if len(ckan_users) > 0:
        ckan_user = ckan_users[0]
        log.debug('CKAN user found: {} for {}'.format(ckan_user, email))
        return ckan_user
    log.debug('CKAN user not found for {}'.format(email))


def create_user(context, email, firstname, lastname):
    """ Create a new CKAN user from saml """
    data_dict = {
        u'name': _get_random_username_from_email(email),
        u'fullname': u'{0} {1}'.format(firstname, lastname),
        u'email': email,
        u'password': h.generate_password()
    }

    try:
        return logic.get_action(u'user_create')(context, data_dict)
        log.info('CKAN user created: {}'.format(data_dict['name']))
    except logic.ValidationError as e:
        error_message = (e.error_summary or e.message or e.error_dict)
        log.error(error_message)
        base.abort(400, error_message)


def acs():
    u'''The location where the SAML assertion is sent with a HTTP POST.
    This is often referred to as the SAML Assertion Consumer Service (ACS) URL.
    '''
    log.debug('Getting an external redirection')
    g.user = None
    g.userobj = None

    context = {
        u'ignore_auth': True,
        u'keep_email': True,
        u'model': model
    }

    saml_user_firstname = \
        config.get(u'ckanext.saml2auth.user_firstname')
    saml_user_lastname = \
        config.get(u'ckanext.saml2auth.user_lastname')
    saml_user_email = \
        config.get(u'ckanext.saml2auth.user_email')

    config_sp = sp_config()
    saml_response = request.form.get(u'SAMLResponse', None)
    log.debug('Validating user with config {} for response {} ...'.format(config_sp, saml_response[:30]))
    client = h.saml_client(config_sp)
    try:
        auth_response = client.parse_authn_request_response(
            saml_response,
            BINDING_HTTP_POST)
    except Exception as e:
        error = 'Bad login request: {}'.format(e)
        log.error(error)
        extra_vars = {u'code': [400], u'content': error}
        return base.render(u'error_document_template.html', extra_vars), 400

    if auth_response is None:
        log.error('Empty login request')
        extra_vars = {u'code': [400], u'content': u'Empty login request.'}
        return base.render(u'error_document_template.html', extra_vars), 400

    auth_response.get_identity()
    # SAML username - unique
    # TODO use to connect CKAN user and SAML user
    user_info = auth_response.get_subject()
    saml_id = user_info.text
    log.debug('User info {} SAML id {}'.format(user_info, saml_id))

    # Required user attributes for user creation
    email = auth_response.ava[saml_user_email][0]

    firstname = auth_response.ava.get(saml_user_firstname, [email.split('@')[0]])[0]
    lastname = auth_response.ava.get(saml_user_lastname, [email.split('@')[1]])[0]

    # Check if CKAN-SAML user exists for the current SAML login
    user = get_ckan_user(email)

    if not user:
        user_dict = create_user(context, email, firstname, lastname)
    else:
        # If account exists and is deleted, reactivate it.
        h.activate_user_if_deleted(user)
        user_dict = model_dictize.user_dictize(user, context)

    g.user = user_dict['name']

    # Check if the authenticated user email is in given list of emails
    # and make that user sysadmin and opposite
    h.update_user_sysadmin_status(g.user, email)

    g.userobj = model.User.by_name(g.user)
    # log the user in programmatically
    resp = toolkit.redirect_to(u'user.me')
    set_repoze_user(g.user, resp)
    log.debug('User {} OK, redirecting'.format(g.user))

    return resp


def get_requested_authn_contexts():
    requested_authn_contexts = config.get('ckanext.saml2auth.requested_authn_context', None)
    if requested_authn_contexts is None or requested_authn_contexts == '':
        return []

    return requested_authn_contexts.strip().split()


def saml2login():
    u'''Redirects the user to the
     configured identity provider for authentication
    '''
    client = h.saml_client(sp_config())
    requested_authn_contexts = get_requested_authn_contexts()

    if len(requested_authn_contexts) > 0:
        comparison = config.get('ckanext.saml2auth.requested_authn_context_comparison', 'minimum')
        if comparison not in ['exact', 'minimum', 'maximum', 'better']:
            error = 'Unexpected comparison value {}'.format(comparison)
            raise ValueError(error)

        final_context = requested_authn_context(
            class_ref=requested_authn_contexts,
            comparison=comparison
        )

        reqid, info = client.prepare_for_authenticate(requested_authn_context=final_context)
    else:
        reqid, info = client.prepare_for_authenticate()

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
