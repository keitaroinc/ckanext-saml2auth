[![CI][]][1] [![Coverage][]][2] [![Gitter][]][3] [![Pypi][]][4] [![Python][]][5] [![CKAN][]][6]

# ckanext-saml2auth

A [CKAN](https://ckan.org) extension to enable Single Sign-On (SSO) for CKAN data portals via SAML2 Authentication.

## Requirements

This extension works with CKAN 2.9+.

## Installation

To install ckanext-saml2auth:

1.  Install the required system packages:

        sudo apt install xmlsec1

2.  Activate your CKAN virtual environment, for example:

        . /usr/lib/ckan/default/bin/activate

3.  Install the required system packages to install the necessary python
    module dependencies:

        # rustc and cargo are neeeded to build cryptography if no binary wheel exists
        sudo apt install rustc cargo

4.  Install the ckanext-saml2auth Python package into your virtual
    environment:

        pip install ckanext-saml2auth

5.  Add `saml2auth` to the `ckan.plugins` setting in your CKAN config
    file (by default the config file is located at
    `/etc/ckan/default/ckan.ini`).

6.  Restart CKAN. For example if you\'ve deployed CKAN with Apache on
    Ubuntu:

        sudo service apache2 reload

## Config settings

Required:

    # Specifies the metadata location type
    # Options: local or remote
    ckanext.saml2auth.idp_metadata.location = remote

    # Path to a local file accessible on the server the service runs on
    # Ignore this config if the idp metadata location is set to: remote
    ckanext.saml2auth.idp_metadata.local_path = /opt/metadata/idp.xml

    # A remote URL serving aggregate metadata
    # Ignore this config if the idp metadata location is set to: local
    ckanext.saml2auth.idp_metadata.remote_url = https://kalmar2.org/simplesaml/module.php/aggregator/?id=kalmarcentral2&set=saml2

    # Path to a local file accessible on the server the service runs on
    # Ignore this config if the idp metadata location is set to: local and metadata is public
    ckanext.saml2auth.idp_metadata.remote_cert = /opt/metadata/kalmar2.cert

    # Corresponding SAML user field for firstname
    ckanext.saml2auth.user_firstname = firstname

    # Corresponding SAML user field for lastname
    ckanext.saml2auth.user_lastname = lastname

    # Corresponding SAML user field for fullname
    # (Optional: Can be used as an alternative to firstname + lastname)
    ckanext.saml2auth.user_fullname = fullname

    # Corresponding SAML user field for email
    ckanext.saml2auth.user_email = email


Optional:

    # URL route of the endpoint where the SAML assertion is sent, also known as Assertion Consumer Service (ACS).
    # Default: /acs
    ckanext.saml2auth.acs_endpoint = /sso/post

    # Configuration setting that enables CKAN's internal register/login functionality as well
    # Default: False
    ckanext.saml2auth.enable_ckan_internal_login = True

    # List of email addresses from users that should be created as sysadmins (system administrators)
    # Note that this means that CKAN sysadmins will _only_ be managed based on this config option and will override existing user permissions in the CKAN database
    # If not set then it is ignored and CKAN sysadmins are managed through normal means
    # Default: <Not set>
    ckanext.saml2auth.sysadmins_list = mail@domain.com mail2@domain.com mail3@domain.com

    # Indicates that attributes that are not recognized (they are not configured in attribute-mapping),
    # will not be discarded.
    # Default: True
    ckanext.saml2auth.allow_unknown_attributes = False

    # A list of string values that will be used to set the <NameIDFormat> element of the metadata of an entity.
    # Default: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
    ckanext.saml2auth.sp.name_id_format = urn:oasis:names:tc:SAML:2.0:nameid-format:persistent urn:oasis:names:tc:SAML:2.0:nameid-format:transient

    # A string value that will be used to set the Format attribute of the <NameIDPolicy> element of the metadata of an entity.
    # Default: <Not set>
    ckanext.saml2auth.sp.name_id_policy_format = urn:oasis:names:tc:SAML:2.0:nameid-format:persistent

    # Entity ID (also know as Issuer)
    # Define the entity ID. Default is urn:mace:umu.se:saml:ckan:sp
    ckanext.saml2auth.entity_id = urn:gov:gsa:SAML:2.0.profiles:sp:sso:gsa:catalog-dev

    # Signed responses and assertions
    ckanext.saml2auth.want_response_signed = True
    ckanext.saml2auth.want_assertions_signed = False
    ckanext.saml2auth.want_assertions_or_response_signed = False

    # Cert & key files
    ckanext.saml2auth.key_file_path = /path/to/mykey.pem
    ckanext.saml2auth.cert_file_path = /path/to/mycert.pem

    # Attribute map directory
    ckanext.saml2auth.attribute_map_dir = /path/to/dir/attributemaps

    # Authentication context request before redirect to login
    # e.g. to ask for a PIV card with login.gov provider (https://developers.login.gov/oidc/#aal-values) use:
    ckanext.saml2auth.requested_authn_context = http://idmanagement.gov/ns/assurance/aal/3?hspd12=true
    # You can use multiple context separated by spaces
    ckanext.saml2auth.requested_authn_context = req1 req2

    # Define the comparison value for RequestedAuthnContext
    # Comparison could be one of this: exact, minimum, maximum or better
    ckanext.saml2auth.requested_authn_context_comparison = exact

    # Indicates if this entity will sign the Logout Requests originated from it
    ckanext.saml2auth.logout_requests_signed = False

    # Saml logout request preferred binding settings variable
    # Default: urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
    ckanext.saml2auth.logout_expected_binding =  urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST

    # Default fallback endpoint to redirect to if no RelayState provided in the SAML Response
    # Default: user.me (ie /dashboard)
    # e.g. to redirect to the home page
    ckanext.saml2auth.default_fallback_endpoint = home.index

    # If specified, the new users registered on the portal will be put in this organization.
    # You can specify the organization name here or leave it blank.
    # When left blank (the default), the new users are not added to any organization.
    ckanext.saml2auth.user_default_org=
    # The default role for the new users in the specified organization.
    # This is not activated unless ckanext.saml2auth.user_default_org is set.
    # The possible values are: member, editor or admin - the role for the user when
    # added in the organization.
    # If unset, the user would get a role of 'member' in the organization.
    ckanext.saml2auth.user_default_role=

## Plugin interface

This extension provides the [ISaml2Auth]{.title-ref} interface that
allows other plugins to hook into the Saml2 authorization flow. This
allows plugins to integrate custom logic like:

-   Include additional attributes returned via the IdP as
    [plugin_extras]{.title-ref} in the CKAN users
-   Assign users to specific organizations with specific roles based on
    Saml2 attributes
-   Customize the flow response, to eg issue redirects or include custom
    headers.

For a list of available methods and their parameters check the
[`ckanext/saml2auth/interfaces.py`](ckanext/saml2auth/interfaces.py)
file, and for a basic example see the
[`ExampleISaml2AuthPlugin`](ckanext/saml2auth/tests/test_interface.py)
class.

## Developer installation

To install ckanext-saml2auth for development, activate your CKAN
virtualenv and do:

    sudo apt install xmlsec1
    git clone https://github.com/duskobogdanovski/ckanext-saml2auth.git
    cd ckanext-saml2auth
    python setup.py develop
    pip install -r dev-requirements.txt

## Tests

To run the tests, do:

    pytest --ckan-ini=test.ini

To run the tests and produce a coverage report, first make sure you have
`pytest-cov` installed in your virtualenv (`pip install pytest-cov`)
then run:

    pytest --ckan-ini=test.ini  --cov=ckanext.saml2auth

## Releasing a new version of ckanext-saml2auth

ckanext-saml2auth should be available on PyPI as
<https://pypi.org/project/ckanext-saml2auth>. To publish a new version
to PyPI follow these steps:

1.  Update the version number in the `setup.py` file. See [PEP
    440](http://legacy.python.org/dev/peps/pep-0440/#public-version-identifiers)
    for how to choose version numbers.

2.  Make sure you have the latest version of necessary packages:

        pip install --upgrade setuptools wheel twine

3.  Create a source and binary distributions of the new version:

        python setup.py sdist bdist_wheel && twine check dist/*

    Fix any errors you get.

4.  Upload the source distribution to PyPI:

        twine upload dist/*

5.  Commit any outstanding changes:

        git commit -a
        git push

6.  Tag the new release of the project on GitHub with the version number
    from the `setup.py` file. For example if the version number in
    `setup.py` is 0.0.1 then do:

        git tag 0.0.1
        git push --tags
        

  [CI]: https://github.com/keitaroinc/ckanext-saml2auth/workflows/CI/badge.svg
  [1]: https://github.com/keitaroinc/ckanext-saml2auth/actions
  [Coverage]: https://coveralls.io/repos/github/keitaroinc/ckanext-saml2auth/badge.svg?branch=main
  [2]: https://coveralls.io/github/keitaroinc/ckanext-saml2auth?branch=main
  [Gitter]: https://badges.gitter.im/keitaroinc/ckan.svg
  [3]: https://gitter.im/keitaroinc/ckan?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge
  [Pypi]: https://img.shields.io/pypi/v/ckanext-saml2auth
  [4]: https://pypi.org/project/ckanext-saml2auth
  [Python]: https://img.shields.io/badge/python-3.7%20%7C%203.8%20%7C%203.9-blue
  [5]: https://www.python.org
  [CKAN]: https://img.shields.io/badge/ckan-2.9%20%7C%202.10-yellow
  [6]: https://www.ckan.org
