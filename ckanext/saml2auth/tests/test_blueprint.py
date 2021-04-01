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
import os
import pytest

from ckan.plugins.toolkit import url_for

here = os.path.dirname(os.path.abspath(__file__))
extras_folder = os.path.join(here, 'extras')


@pytest.mark.usefixtures(u'clean_db', u'clean_index')
@pytest.mark.ckan_config(u'ckan.plugins', u'saml2auth')
class TestBlueprint(object):

    def test_user_register_disabled_by_default(self, app):
        url = url_for(u'user.register')
        response = app.get(url=url)
        assert 403 == response.status_code

        assert u'This resource is forbidden' \
               u' by the system administrator. ' \
               u'Only SSO through SAML2 authorization ' \
               u'is available at this moment.' in response

    def test_internal_user_login_disabled_by_deafult(self, app):
        url = url_for(u'user.login')
        response = app.get(url=url)
        assert 403 == response.status_code

        assert u'This resource is forbidden' \
               u' by the system administrator. ' \
               u'Only SSO through SAML2 authorization ' \
               u'is available at this moment.' in response

    @pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
    @pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.local_path',
                             os.path.join(extras_folder, 'provider2', 'idp.xml'))
    def test_came_from_sent_as_relay_state(self, app):

        url = url_for('saml2auth.saml2login', came_from='/dataset/my-dataset')

        response = app.get(url=url, follow_redirects=False)
        assert 'RelayState=%2Fdataset%2Fmy-dataset' in response.headers['Location']
