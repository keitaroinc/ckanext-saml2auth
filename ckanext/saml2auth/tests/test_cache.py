from ckanext.saml2auth.cache import set_subject_id, get_subject_id, get_saml_session_info
from types import SimpleNamespace
from saml2.ident import code

nameid = SimpleNamespace(
    name_qualifier="issuer.example.com",
    sp_name_qualifier="sp.example.com",
    text="user123",
    format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    sp_provided_id=None
)


def test_set_subject_id_with_string():
    session = {}
    set_subject_id(session, "user123")
    assert session['_saml2_subject_id'] == "user123"


def test_set_subject_id_with_nameid_like_object():
    session = {}
    expected_code = code(nameid)
    set_subject_id(session, nameid)
    assert session['_saml2_subject_id'] == expected_code


def test_get_subject_id_missing():
    session = {}
    result = get_subject_id(session)
    assert result is None


def test_get_subject_id_with_real_code_decode():

    encoded = code(nameid)
    session = {'_saml2_subject_id': encoded}

    result = get_subject_id(session)

    assert result.name_qualifier == nameid.name_qualifier
    assert result.sp_name_qualifier == nameid.sp_name_qualifier
    assert result.format == nameid.format
    assert result.text == nameid.text
    assert result.sp_provided_id == nameid.sp_provided_id


def test_get_saml_session_info_with_encoded_nameid():

    encoded_nameid = code(nameid)
    session = {
        '_saml_session_info': {
            'name_id': encoded_nameid,
            'other_data': 'example'
        }
    }

    result = get_saml_session_info(session)

    assert isinstance(result['name_id'], object)
    assert result['name_id'].name_qualifier == nameid.name_qualifier
    assert result['name_id'].sp_name_qualifier == nameid.sp_name_qualifier
    assert result['name_id'].text == nameid.text
    assert result['name_id'].format == nameid.format
    assert result['name_id'].sp_provided_id == nameid.sp_provided_id
    assert result['other_data'] == 'example'


def test_get_saml_session_info_with_decoded_nameid():

    session = {
        '_saml_session_info': {
            'name_id': nameid,
            'foo': 'bar'
        }
    }

    result = get_saml_session_info(session)

    assert result['name_id'] == nameid
    assert result['foo'] == 'bar'


def test_get_saml_session_info_missing():
    session = {}
    result = get_saml_session_info(session)
    assert result is None
