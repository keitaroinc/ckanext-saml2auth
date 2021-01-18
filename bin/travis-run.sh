#!/bin/bash
set -e

nosetests --ckan --with-pylons=subdir/test.ini --with-coverage --cover-package=ckanext ckanext/saml2auth/tests
flake8 . --count --max-complexity=10 --max-line-length=127 --statistics --exclude ckan
