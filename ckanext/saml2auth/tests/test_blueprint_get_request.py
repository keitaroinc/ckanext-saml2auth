# encoding: utf-8
import base64
from datetime import datetime, timedelta
from jinja2 import Template
from nose.tools import assert_equal, assert_in
import os
from saml import schema
from ckan.tests.helpers import FunctionalTestBase, change_config
from ckan import model

from saml2.xmldsig import SIG_RSA_SHA256
from saml2.xmldsig import DIGEST_SHA256
from saml2.saml import NAMEID_FORMAT_ENTITY
from saml2.saml import Issuer
from saml2.server import Server
from saml2.authn_context import INTERNETPROTOCOLPASSWORD

here = os.path.dirname(os.path.abspath(__file__))
extras_folder = os.path.join(here, 'extras')
responses_folder = os.path.join(here, 'responses')


class TestGetRequest(FunctionalTestBase):
    """ test getting request from external source """

    @change_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
    @change_config(u'ckanext.saml2auth.idp_metadata.local_path', os.path.join(extras_folder, 'provider0', 'idp.xml'))
    @change_config(u'ckanext.saml2auth.want_response_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_or_response_signed', u'False')
    def test_empty_request(self):
        app = self._get_test_app()
        url = '/acs'
        data = {
            'SAMLResponse': ''
        }
        response = app.post(url=url, status=400, expect_errors=True, params=data)
        assert_equal(400, response.status_int)
        assert_in(u'Empty login request', response)

    @change_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
    @change_config(u'ckanext.saml2auth.idp_metadata.local_path', os.path.join(extras_folder, 'provider0', 'idp.xml'))
    @change_config(u'ckanext.saml2auth.want_response_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_or_response_signed', u'False')
    def test_bad_request(self):
        app = self._get_test_app()
        url = '/acs'
        data = {
            'SAMLResponse': '<saml>'
        }
        response = app.post(url=url, status=400, expect_errors=True, params=data)
        assert_equal(400, response.status_int)
        assert_in(u'Bad login request', response)

    @change_config(u'ckanext.saml2auth.entity_id', u'urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity')
    @change_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
    @change_config(u'ckanext.saml2auth.idp_metadata.local_path', os.path.join(extras_folder, 'provider0', 'idp.xml'))
    @change_config(u'ckanext.saml2auth.want_response_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_or_response_signed', u'False')
    def test_unsigned_request(self):

        # read about saml2 responses: https://www.samltool.com/generic_sso_res.php
        unsigned_response_file = os.path.join(responses_folder, 'unsigned0.xml')
        unsigned_response = open(unsigned_response_file).read()
        # parse values
        context = {
            'entity_id': 'urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity',
            'destination': 'http://test.ckan.net/acs',
            'recipient': 'http://test.ckan.net/acs',
            'issue_instant': datetime.now().isoformat()
        }
        t = Template(unsigned_response)
        final_response = t.render(**context)

        encoded_response = base64.b64encode(final_response)

        app = self._get_test_app()
        url = '/acs'

        data = {
            'SAMLResponse': encoded_response
        }
        response = app.post(url=url, params=data)
        # we expect a redirection after login
        assert_equal(302, response.status_int)

    def render_file(self, path, context, save_as=None):
        """ open file and render contect values """
        txt = open(path).read()
        t = Template(txt)
        response = t.render(**context)

        if save_as is not None:
            f = open(save_as, 'w')
            f.write(response)
            f.close()

        return response

    @change_config(u'ckanext.saml2auth.entity_id', u'urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity')
    @change_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
    @change_config(u'ckanext.saml2auth.idp_metadata.local_path', os.path.join(extras_folder, 'provider1', 'idp.xml'))
    @change_config(u'ckanext.saml2auth.want_response_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_or_response_signed', u'False')
    def test_saml_response(self):

        destination = 'http://test.ckan.net/acs'
        instant = datetime.now()
        not_before = instant - timedelta(hours=1)
        not_after = instant + timedelta(hours=1)
        entity_id = 'urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity'
        issuer_url = 'https://organization.com/saml'

        context = {
            'entity_id': 'urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity',
            'entity_session_id': '_session_ID_44444',
            'issuer_url': issuer_url,
            'destination': destination,
            'issue_instant': instant,
            'org_name': 'IDP Organization',
            'org_url': 'https://idp.organization.com',
            'redirect_login_url': 'https://idp.organization.com/auth',
            'attributes_url': 'https://idp.organization.com/attributes'
        }

        self.render_file(
            path=os.path.join(extras_folder, 'provider1', 'idp_template.xml'),
            context=context,
            save_as=os.path.join(extras_folder, 'provider1', 'idp.xml')
        )

        document = schema.Response()
        document.id = '11111111-1111-1111-1111-111111111111'
        document.in_response_to = '22222222-2222-2222-2222-222222222222'
        document.issue_instant = instant
        document.issuer = entity_id
        document.destination = destination
        document.status.code.value = schema.StatusCode.SUCCESS

        # Create an assertion for the response.
        document.assertions = assertion = schema.Assertion()
        assertion.id = '33333333-3333-3333-3333-333333333333'
        assertion.issue_instant = instant
        assertion.issuer = issuer_url

        # Create a subject.
        assertion.subject = schema.Subject()
        assertion.subject.principal = '44444444-4444-4444-4444-444444444444'
        assertion.subject.principal.format = schema.NameID.Format.TRANSIENT
        data = schema.SubjectConfirmationData()
        data.in_response_to = '22222222-2222-2222-2222-222222222222'
        data.not_on_or_after = not_after
        data.recipient = destination
        confirmation = schema.SubjectConfirmation()
        confirmation.data = data
        assertion.subject.confirmation = confirmation

        # Create an authentication statement.
        statement = schema.AuthenticationStatement()
        assertion.statements.append(statement)
        statement.authn_instant = instant
        statement.session_index = '33333333-3333-3333-3333-333333333333'
        reference = schema.AuthenticationContextReference
        statement.context.reference = reference.PASSWORD_PROTECTED_TRANSPORT

        # Create a authentication condition.
        assertion.conditions = conditions = schema.Conditions()
        conditions.not_before = not_before
        conditions.not_on_or_after = not_after
        condition = schema.AudienceRestriction()
        condition.audiences = entity_id
        conditions.condition = condition

        # Create attributes
        email = schema.Attribute(name='email')
        email.name_ = 'email'
        email.value = schema.AttributeValue('example@email.com')
        attributes = schema.AttributeStatement()
        attributes.attributes.append(email)
        assertion.statements.append(attributes)

        final_response = document.tostring()
        f = open(os.path.join(extras_folder, 'provider1', 'test-simple.xml'), 'w')
        f.write(final_response)
        f.close()
        encoded_response = base64.b64encode(final_response)

        app = self._get_test_app()
        url = '/acs'

        data = {
            'SAMLResponse': encoded_response
        }
        response = app.post(url=url, params=data)
        # we expect a redirection after login
        assert_equal(302, response.status_int)

    def _load_base(
        self,
        destination='http://test.ckan.net/acs',
        issuer_url='https://organization.com/saml/',
        entity_id='urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity'
    ):

        cert_file = os.path.join(extras_folder, 'provider1', 'mycert.pem')
        f = open(cert_file)
        cert = f.read()
        f.close()

        x509_cert = cert.replace('\x0D', '')
        x509_cert = x509_cert.replace('\r', '')
        x509_cert = x509_cert.replace('\n', '')
        x509_cert = x509_cert.replace('-----BEGIN CERTIFICATE-----', '')
        x509_cert = x509_cert.replace('-----END CERTIFICATE-----', '')
        x509_cert = x509_cert.replace(' ', '')

        self.context = {
            'entity_id': entity_id,
            'entity_session_id': '_session_ID_44444',
            'issuer_url': issuer_url,
            'destination': destination,
            'org_name': 'IDP Organization',
            'org_url': 'https://idp.organization.com',
            'redirect_login_url': 'https://idp.organization.com/auth',
            'attributes_url': 'https://idp.organization.com/attributes',
            'certificate': x509_cert
        }

        self.render_file(
            path=os.path.join(extras_folder, 'provider1', 'idp_cert_template.xml'),
            context=self.context,
            save_as=os.path.join(extras_folder, 'provider1', 'idp.xml')
        )

        key_file = os.path.join(extras_folder, 'provider1', 'mykey.pem')
        cert_file = os.path.join(extras_folder, 'provider1', 'mycert.pem')
        self.config = {
            'description': 'CKAN saml2 Service Provider',
            'service': {
                'sp': {
                    'name_id_format': [
                        'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                        'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                        'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress'
                    ],
                    'want_response_signed': False,
                    'name': 'CKAN SP',
                    'want_assertions_signed': True,
                    'allow_unsolicited': True,
                    'endpoints': {
                        'assertion_consumer_service': ['http://ckan:5000/acs', 'http://test.ckan.net/acs']
                    },
                    'want_assertions_or_response_signed': True,
                    'name_id_policy_format': [
                        'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                        'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                        'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress'
                    ]
                }
            },
            'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
            'debug': 0,
            'entityid': entity_id,
            'allow_unknown_attributes': 'true',
            'metadata': {
                'local': [os.path.join(extras_folder, 'provider1', 'idp.xml')]
            },
            'key_file': key_file,
            'cert_file': cert_file,
            'encryption_keypairs': [
                {'key_file': key_file, 'cert_file': cert_file}
                ]
        }

    def _generate_cert(self):
        from saml2.cert import OpenSSLWrapper

        cert_info_ca = {
            "cn": "localhost.ca",
            "country_code": "se",
            "state": "ac",
            "city": "umea",
            "organization": "Test University",
            "organization_unit": "Deca"
        }

        osw = OpenSSLWrapper()
        ca_cert, ca_key = osw.create_certificate(
            cert_info_ca,
            request=False,
            write_to_file=False
        )

        cert_str, key_str = osw.create_certificate(cert_info_ca, request=True)
        re_cert_str = osw.create_cert_signed_certificate(
            ca_cert,
            ca_key,
            cert_str,
            valid_from=0,
            valid_to=1
        )

        f = open(os.path.join(extras_folder, 'provider1', 'mycert.pem'), 'w')
        f.write(re_cert_str)
        f.close()

        f = open(os.path.join(extras_folder, 'provider1', 'mykey.pem'), 'w')
        f.write(key_str)
        f.close()

        self.key_str = key_str
        self.cert_str = re_cert_str

    @change_config(u'ckanext.saml2auth.entity_id', u'urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity')
    @change_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
    @change_config(u'ckanext.saml2auth.idp_metadata.local_path', os.path.join(extras_folder, 'provider1', 'idp.xml'))
    @change_config(u'ckanext.saml2auth.want_response_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_or_response_signed', u'True')
    @change_config(u'ckanext.saml2auth.key_file_path', os.path.join(extras_folder, 'provider1', 'mykey.pem'))
    @change_config(u'ckanext.saml2auth.cert_file_path', os.path.join(extras_folder, 'provider1', 'mycert.pem'))
    def test_encrypted_assertion(self):

        self._generate_cert()
        self._load_base()

        # define the user identity
        IDENTITY = {
            "eduPersonAffiliation": ["staff", "member"],
            "surName": ["Jeter"], "givenName": ["Derek"],
            "email": ["foo@gmail.com"],
            "title": ["shortstop"]
        }

        # start a server to generate the expected response
        server = Server(self.config)
        name_id = server.ident.transient_nameid(self.context['entity_id'], "id12")
        issuer = Issuer(text=self.context['entity_id'], format=NAMEID_FORMAT_ENTITY)
        authn = {
            "class_ref": INTERNETPROTOCOLPASSWORD,
            "authn_auth": "http://www.example.com/login"
        }
        response = server.create_authn_response(
            identity=IDENTITY,
            in_response_to="id12",
            destination=self.context['destination'],
            sp_entity_id=self.context['entity_id'],
            name_id=name_id,
            sign_assertion=True,
            sign_response=True,
            issuer=issuer,
            sign_alg=SIG_RSA_SHA256,
            digest_alg=DIGEST_SHA256,
            encrypt_assertion=True,
            encrypt_cert_assertion=self.cert_str,
            encrypt_assertion_self_contained=True,
            authn=authn
        )

        # finishe the response and b64 encode to send to our /acs endpoint
        final_signed_response = response  # .to_string()

        # To check the response
        f = open(os.path.join(extras_folder, 'provider1', 'test-signed-encrypted.xml'), 'w')
        f.write(final_signed_response)
        f.close()
        encoded_response = base64.b64encode(final_signed_response)

        app = self._get_test_app()
        url = '/acs'

        data = {
            'SAMLResponse': encoded_response
        }
        response = app.post(url=url, params=data)
        # we expect a redirection after login
        assert_equal(302, response.status_int)

    @change_config(u'ckanext.saml2auth.entity_id', u'urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity')
    @change_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
    @change_config(u'ckanext.saml2auth.idp_metadata.local_path', os.path.join(extras_folder, 'provider1', 'idp.xml'))
    @change_config(u'ckanext.saml2auth.want_response_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_or_response_signed', u'True')
    @change_config(u'ckanext.saml2auth.key_file_path', os.path.join(extras_folder, 'provider1', 'mykey.pem'))
    @change_config(u'ckanext.saml2auth.cert_file_path', os.path.join(extras_folder, 'provider1', 'mycert.pem'))
    def test_signed_not_encrypted_assertion(self):

        self._generate_cert()
        self._load_base()

        # define the user identity
        IDENTITY = {
            "eduPersonAffiliation": ["staff", "member"],
            "surName": ["Jeter"], "givenName": ["Derek"],
            "email": ["foo@gmail.com"],
            "title": ["shortstop"]
        }

        # start a server to generate the expected response
        server = Server(self.config)
        name_id = server.ident.transient_nameid(self.context['entity_id'], "id12")
        issuer = Issuer(text=self.context['entity_id'], format=NAMEID_FORMAT_ENTITY)
        authn = {
            "class_ref": INTERNETPROTOCOLPASSWORD,
            "authn_auth": "http://www.example.com/login"
        }
        response = server.create_authn_response(
            identity=IDENTITY,
            in_response_to="id12",
            destination=self.context['destination'],
            sp_entity_id=self.context['entity_id'],
            name_id=name_id,
            sign_assertion=True,
            sign_response=True,
            issuer=issuer,
            sign_alg=SIG_RSA_SHA256,
            digest_alg=DIGEST_SHA256,
            authn=authn
        )

        # finishe the response and b64 encode to send to our /acs endpoint
        final_signed_response = response  # .to_string()

        # To check the response
        f = open(os.path.join(extras_folder, 'provider1', 'test-signed.xml'), 'w')
        f.write(final_signed_response)
        f.close()
        encoded_response = base64.b64encode(final_signed_response)

        app = self._get_test_app()
        url = '/acs'

        data = {
            'SAMLResponse': encoded_response
        }
        response = app.post(url=url, params=data)
        # we expect a redirection after login
        assert_equal(302, response.status_int)

    @change_config(u'ckanext.saml2auth.entity_id', u'urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity')
    @change_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
    @change_config(u'ckanext.saml2auth.idp_metadata.local_path', os.path.join(extras_folder, 'provider0', 'idp.xml'))
    @change_config(u'ckanext.saml2auth.want_response_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_or_response_signed', u'False')
    def test_user_fullname_using_first_last_name(self):

        # read about saml2 responses: https://www.samltool.com/generic_sso_res.php
        unsigned_response_file = os.path.join(responses_folder, 'unsigned0.xml')
        unsigned_response = open(unsigned_response_file).read()
        # parse values
        context = {
            'entity_id': 'urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity',
            'destination': 'http://test.ckan.net/acs',
            'recipient': 'http://test.ckan.net/acs',
            'issue_instant': datetime.now().isoformat()
        }
        t = Template(unsigned_response)
        final_response = t.render(**context)

        encoded_response = self._b4_encode_string(final_response)

        app = self._get_test_app()
        url = '/acs'

        data = {
            'SAMLResponse': encoded_response
        }
        response = app.post(url=url, params=data)
        assert_equal(200, response.status_code)

        user = model.User.by_email('test@example.com')[0]

        assert_equal(user.fullname, 'John Smith')

    @change_config(u'ckanext.saml2auth.entity_id', u'urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity')
    @change_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
    @change_config(u'ckanext.saml2auth.idp_metadata.local_path', os.path.join(extras_folder, 'provider0', 'idp.xml'))
    @change_config(u'ckanext.saml2auth.want_response_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_signed', u'False')
    @change_config(u'ckanext.saml2auth.want_assertions_or_response_signed', u'False')
    @change_config(u'ckanext.saml2auth.user_fullname', u'fullname')
    @change_config(u'ckanext.saml2auth.user_firstname', None)
    @change_config(u'ckanext.saml2auth.user_lastname', None)
    def test_user_fullname_using_fullname(self):

        # read about saml2 responses: https://www.samltool.com/generic_sso_res.php
        unsigned_response_file = os.path.join(responses_folder, 'unsigned0.xml')
        unsigned_response = open(unsigned_response_file).read()
        # parse values
        context = {
            'entity_id': 'urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity',
            'destination': 'http://test.ckan.net/acs',
            'recipient': 'http://test.ckan.net/acs',
            'issue_instant': datetime.now().isoformat()
        }
        t = Template(unsigned_response)
        final_response = t.render(**context)

        encoded_response = self._b4_encode_string(final_response)

        app = self._get_test_app()
        url = '/acs'

        data = {
            'SAMLResponse': encoded_response
        }
        response = app.post(url=url, params=data)
        assert_equal(200, response.status_code)

        user = model.User.by_email('test@example.com')[0]

        assert_equal(user.fullname, 'John Smith (Operations)')
