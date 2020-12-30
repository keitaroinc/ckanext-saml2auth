#!/bin/sh -e

if [ $TEST_FOLDER = "test_py2_ckan28" ]
then
    nosetests --ckan --with-pylons=subdir/test.ini ckanext/saml2auth/tests/${TEST_FOLDER}
else
    pytest --ckan-ini=subdir/test.ini --cov=ckanext.saml2auth --disable-warnings ckanext/saml2auth/tests/${TEST_FOLDER}
fi

flake8 . --count --max-complexity=10 --max-line-length=127 --statistics --exclude ckan,ckanext-saml2auth
