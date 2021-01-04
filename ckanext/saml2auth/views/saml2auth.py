# encoding: utf-8
from flask import Blueprint
from saml2 import BINDING_HTTP_POST

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


def get_ckan_user(email):
    """ Look for a CKAN user with given email.
        Activate the user if it's deleted
        """
    ckan_users = model.User.by_email(email)
    if len(ckan_users) > 0:
        ckan_user = ckan_users[0]
        return ckan_user


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
    except logic.ValidationError as e:
        error_message = (e.error_summary or e.message or e.error_dict)
        base.abort(400, error_message)


def acs():
    u'''The location where the SAML assertion is sent with a HTTP POST.
    This is often referred to as the SAML Assertion Consumer Service (ACS) URL.
    '''
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

    client = h.saml_client(sp_config())
    auth_response = client.parse_authn_request_response(
        request.form.get(u'SAMLResponse', None),
        BINDING_HTTP_POST)
    auth_response.get_identity()

    # SAML username - unique
    # TODO use to connect CKAN user and SAML user
    # user_info = auth_response.get_subject()
    # saml_id = user_info.text

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

    # If user email is in given list of emails
    # make that user sysadmin and opposite
    h.update_user_sysadmin_status(g.user, email)

    g.userobj = model.User.by_name(g.user)
    # log the user in programmatically
    resp = toolkit.redirect_to(u'user.me')
    set_repoze_user(g.user, resp)
    return resp


def saml2login():
    u'''Redirects the user to the
     configured identity provider for authentication
    '''
    client = h.saml_client(sp_config())
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


saml2auth.add_url_rule(u'/acs', view_func=acs, methods=[u'GET', u'POST'])

if not h.is_default_login_enabled():
    saml2auth.add_url_rule(u'/user/login', view_func=saml2login)
    saml2auth.add_url_rule(
        u'/user/register', view_func=disable_default_login_register)
else:
    saml2auth.add_url_rule(u'/user/saml2login', view_func=saml2login)
