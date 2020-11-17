#!/bin/sh -e

pytest --ckan-ini=subdir/test.ini --cov=ckanext.saml2auth --disable-warnings ckanext/saml2auth/tests

flake8 . --count --max-complexity=10 --max-line-length=127 --statistics --exclude ckan,ckanext-saml2auth
