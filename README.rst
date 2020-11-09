.. You should enable this project on travis-ci.org and coveralls.io to make
   these badges work. The necessary Travis and Coverage config files have been
   generated for you.

.. image:: https://travis-ci.org/duskobogdanovski/ckanext-saml2auth.svg?branch=master
    :target: https://travis-ci.org/duskobogdanovski/ckanext-saml2auth

.. image:: https://coveralls.io/repos/duskobogdanovski/ckanext-saml2auth/badge.svg
  :target: https://coveralls.io/r/duskobogdanovski/ckanext-saml2auth

.. image:: https://img.shields.io/pypi/v/ckanext-saml2auth.svg
    :target: https://pypi.org/project/ckanext-saml2auth/
    :alt: Latest Version

.. image:: https://img.shields.io/pypi/pyversions/ckanext-saml2auth.svg
    :target: https://pypi.org/project/ckanext-saml2auth/
    :alt: Supported Python versions

.. image:: https://img.shields.io/pypi/status/ckanext-saml2auth.svg
    :target: https://pypi.org/project/ckanext-saml2auth/
    :alt: Development Status

.. image:: https://img.shields.io/pypi/l/ckanext-saml2auth.svg
    :target: https://pypi.org/project/ckanext-saml2auth/
    :alt: License

==================
ckanext-saml2auth
==================

.. Put a description of your extension here:
   What does it do? What features does it have?
   Consider including some screenshots or embedding a video!


------------
Requirements
------------

For example, you might want to mention here which versions of CKAN this
extension works with.


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

4. Add ``saml2auth`` to the ``ckan.plugins`` setting in your CKAN
   config file (by default the config file is located at
   ``/etc/ckan/default/ckan.ini``).

5. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu::

     sudo service apache2 reload


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
     # Ignore this config if the idp metadata location is set to: local
     ckanext.saml2auth.idp_metadata.remote_cert = /opt/metadata/kalmar2.cert

     # Corresponding SAML user field for firstname
     ckanext.saml2auth.user_firstname = firstname

     # Corresponding SAML user field for lastname
     ckanext.saml2auth.user_lastname = lastname

     # Corresponding SAML user field for email
     ckanext.saml2auth.user_email = email


Optional::

     # Configuration setting that enables CKAN's internal register/login functionality as well
     # Default: False
     ckanext.saml2auth.enable_ckan_internal_login = True

     # List of email addresses from users that should be created as sysadmins (system administrators)
     ckanext.saml2auth.sysadmins_list = mail@domain.com mail2@domain.com mail3@domain.com

     # Indicates that attributes that are not recognized (they are not configured in attribute-mapping),
     # will not be discarded.
     # Default: False
     ckanext.saml2auth.allow_unknown_attributes = True

     # A list of string values that will be used to set the <NameIDFormat> element of the metadata of an entity.
     # Default: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
     ckanext.saml2auth.sp.name_id_format = urn:oasis:names:tc:SAML:2.0:nameid-format:persistent urn:oasis:names:tc:SAML:2.0:nameid-format:transient


----------------------
Developer installation
----------------------

To install ckanext-saml2auth for development, activate your CKAN virtualenv and
do::


    sudo apt install xmlsec1
    git clone https://github.com/duskobogdanovski/ckanext-saml2auth.git
    cd ckanext-saml2auth
    python setup.py develop
    pip install -r dev-requirements.txt


-----
Tests
-----

To run the tests, do::

    pytest --ckan-ini=test.ini

To run the tests and produce a coverage report, first make sure you have
``pytest-cov`` installed in your virtualenv (``pip install pytest-cov``) then run::

    pytest --ckan-ini=test.ini  --cov=ckanext.saml2auth


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
