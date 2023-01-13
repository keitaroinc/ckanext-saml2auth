.. You should enable this project on travis-ci.org and coveralls.io to make
   these badges work. The necessary Travis and Coverage config files have been
   generated for you.

.. image:: https://github.com/keitaroinc/ckanext-saml2auth/workflows/CI-CKAN-2.8/badge.svg
    :target: https://github.com/keitaroinc/ckanext-saml2auth/actions

.. image:: https://coveralls.io/repos/github/keitaroinc/ckanext-saml2auth/badge.svg?branch=ckan-2.8
    :target: https://coveralls.io/github/keitaroinc/ckanext-saml2auth?branch=ckan-2.8

.. image:: https://img.shields.io/badge/python-2.7-blue.svg
    :target: https://www.python.org/downloads/release/python-384/




==================
ckanext-saml2auth
==================

.. Put a description of your extension here:
   What does it do? What features does it have?
   Consider including some screenshots or embedding a video!


------------
Requirements
------------

This extension was developed for Python 3 and CKAN 2.9 and then backported to Python 2 + CKAN 2.8.
This branch is about CKAN 2.8 with Python 2.

------------
Installation
------------

.. Add any additional install steps to the list below.
   For example installing any non-Python dependencies or adding any required
   config settings.

To install ckanext-saml2auth:

1. Install the required packages::

     sudo apt install xmlsec1


2. Activate your CKAN virtual environment, for example::

     . /usr/lib/ckan/default/bin/activate

3. Install the ckanext-saml2auth Python package into your virtual environment::

     pip install ckanext-saml2auth


4. Install the python modules required by the extension (adjusting the path according to where ckanext-saml2auth was installed in the previous step)::

    pip install -r requirements.txt

5. Add ``saml2auth`` to the ``ckan.plugins`` setting in your CKAN
   config file (by default the config file is located at
   ``/etc/ckan/default/ckan.ini``).

6. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu::

     sudo service apache2 reload


------------------
CKAN vs SAML users
------------------

| This extension will connect users from external source with local CKAN users using the email.

| If the user does not exist locally, it will be created.

| If the user changes email (in CKAN or external source), this connection will be lost for CKAN 2.8. 
  In CKAN 2.9 the connection will be maintained.

---------------
Config settings
---------------

Required::

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


Optional::

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

----------------------
Developer installation
----------------------

To install ckanext-saml2auth for development, activate your CKAN virtualenv and
do::


    sudo apt install xmlsec1
    git clone https://github.com/keitaroinc/ckanext-saml2auth.git
    cd ckanext-saml2auth
    python setup.py develop
    pip install -r dev-requirements.txt


-----
Tests
-----

To run the tests, do::

    nosetests --ckan --with-pylons=subdir/test.ini ckanext/saml2auth/tests

--------------------------------------------
Releasing a new version of ckanext-saml2auth
--------------------------------------------

ckanext-saml2auth should be available on PyPI as https://pypi.org/project/ckanext-saml2auth.
To publish a new version to PyPI follow these steps:

1. Update the version number in the ``setup.py`` file.
   See `PEP 440 <http://legacy.python.org/dev/peps/pep-0440/#public-version-identifiers>`_
   for how to choose version numbers.

2. Make sure you have the latest version of necessary packages::

    pip install --upgrade setuptools wheel twine

3. Create a source and binary distributions of the new version::

       python setup.py sdist bdist_wheel && twine check dist/*

   Fix any errors you get.

4. Upload the source distribution to PyPI::

       twine upload dist/*

5. Commit any outstanding changes::

       git commit -a
       git push

6. Tag the new release of the project on GitHub with the version number from
   the ``setup.py`` file. For example if the version number in ``setup.py`` is
   0.0.1 then do::

       git tag 0.0.1
       git push --tags
