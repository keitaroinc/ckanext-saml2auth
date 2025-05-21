import pytest
from types import SimpleNamespace
import ckan.model as model
from ckan.tests import factories
from ckan.plugins import toolkit
from ckanext.saml2auth.views.saml2auth import _get_user_by_email


@pytest.fixture
def tdv_data():
    """TestDatasetViews setup data"""
    obj = SimpleNamespace()
    obj.user1 = factories.User(
        email='user1@example.com',
        plugin_extras={'saml2auth': {'saml_id': 'saml_id1'}}
    )
    obj.user2 = factories.User(
        email='user2@example.com',
        plugin_extras={'saml2auth': {'saml_id': 'saml_id2'}}
    )
    return obj


@pytest.mark.usefixtures(u'clean_db', u'clean_index')
@pytest.mark.ckan_config(u'ckan.plugins', u'saml2auth')
class TestDatasetViews(object):
    def test_get_user_by_email_empty(self, tdv_data):
        """ The the function _get_user_by_email for empty response """
        ret = _get_user_by_email('user3@example.com')
        assert ret is None

    def test_get_user_by_email_ok(self, tdv_data):
        """ The the function _get_user_by_email for empty response """
        ret = _get_user_by_email(tdv_data.user1['email'])
        assert ret is not None
        assert ret['email'] == tdv_data.user1['email']

    def test_get_user_by_email_multiple(self, tdv_data):
        """ The the function _get_user_by_email for duplicated emails """
        # Generate a duplciate email
        user2 = model.User.get(tdv_data.user2['id'])
        user2.email = tdv_data.user1['email'].upper()
        model.Session.commit()

        with pytest.raises(toolkit.ValidationError):
            _get_user_by_email(tdv_data.user1['email'])
