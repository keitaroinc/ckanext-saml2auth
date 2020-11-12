# encoding: utf-8
import pytest

import ckan.authz as authz
import ckan.model as model
import ckan.tests.factories as factories
import ckan.tests.helpers as helpers

from ckanext.saml2auth import helpers as h


def test_generate_password():
    password = h.generate_password()
    assert len(password) == 8
    assert type(password) == str


def test_default_login_disabled_by_default():
    assert not h.is_default_login_enabled()


@pytest.mark.ckan_config('ckanext.saml2auth.enable_ckan_internal_login', True)
def test_default_login_enabled():
    assert h.is_default_login_enabled()


@pytest.mark.usefixtures('clean_db', 'clean_index')
@pytest.mark.ckan_config('ckanext.saml2auth.sysadmins_list', '')
def test_00_update_user_sysadmin_status_continue_as_regular():

    user = factories.User(email='useroneemail@example.com')
    h.update_user_sysadmin_status(user['name'], user['email'])
    user_show = helpers.call_action("user_show", id=user["id"])
    is_sysadmin = authz.is_sysadmin(user_show['name'])

    assert not is_sysadmin


@pytest.mark.usefixtures('clean_db', 'clean_index')
@pytest.mark.ckan_config('ckanext.saml2auth.sysadmins_list',
                         'useroneemail@example.com')
def test_01_update_user_sysadmin_status_make_sysadmin():

    user = factories.User(email='useroneemail@example.com')
    h.update_user_sysadmin_status(user['name'], user['email'])
    user_show = helpers.call_action("user_show", id=user["id"])
    is_sysadmin = authz.is_sysadmin(user_show['name'])

    assert is_sysadmin


@pytest.mark.usefixtures('clean_db', 'clean_index')
@pytest.mark.ckan_config('ckanext.saml2auth.sysadmins_list', '')
def test_02_update_user_sysadmin_status_remove_sysadmin_role():

    user = factories.Sysadmin(email='useroneemail@example.com')
    h.update_user_sysadmin_status(user['name'], user['email'])
    user_show = helpers.call_action("user_show", id=user["id"])
    is_sysadmin = authz.is_sysadmin(user_show['name'])

    assert not is_sysadmin


@pytest.mark.usefixtures('clean_db', 'clean_index')
@pytest.mark.ckan_config('ckanext.saml2auth.sysadmins_list',
                         'useroneemail@example.com')
def test_03_update_user_sysadmin_status_continue_as_sysadmin():

    user = factories.Sysadmin(email='useroneemail@example.com')
    h.update_user_sysadmin_status(user['name'], user['email'])
    user_show = helpers.call_action("user_show", id=user["id"])
    is_sysadmin = authz.is_sysadmin(user_show['name'])

    assert is_sysadmin


@pytest.mark.usefixtures('clean_db', 'clean_index')
def test_activate_user_if_deleted():
    user = factories.User()
    user = model.User.get(user["name"])
    user.delete()
    h.activate_user_if_deleted(user)
    assert not user.is_deleted()






