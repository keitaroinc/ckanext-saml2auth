from ckanext.saml2auth.cache import set_subject_id, get_subject_id
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
