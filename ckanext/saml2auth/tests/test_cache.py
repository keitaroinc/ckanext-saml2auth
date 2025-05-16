from ckanext.saml2auth.cache import set_subject_id
from types import SimpleNamespace
from saml2.ident import code


def test_set_subject_id_with_string():
    session = {}
    set_subject_id(session, "user123")
    assert session['_saml2_subject_id'] == "user123"


def test_set_subject_id_with_nameid_like_object():
    session = {}

    nameid = SimpleNamespace(
        name_qualifier="issuer.example.com",
        sp_name_qualifier="sp.example.com",
        text="user123",
        format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        sp_provided_id=None
    )

    expected_code = code(nameid)

    set_subject_id(session, nameid)

    assert session['_saml2_subject_id'] == expected_code
