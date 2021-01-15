#!/bin/bash
set -e

echo "This is travis-build.bash..."

echo "Installing the packages that CKAN requires..."
sudo apt-get update -qq

echo "Installing CKAN and its Python dependencies..."
git clone https://github.com/ckan/ckan
cd ckan
git checkout 2.8

# install the recommended version of setuptools
if [ -f requirement-setuptools.txt ]
then
    echo "Updating setuptools..."
    pip install -r requirement-setuptools.txt
fi

python setup.py develop
pip install -r requirements.txt
pip install -r dev-requirements.txt
cd -

echo "Creating the PostgreSQL user and database..."
sudo -u postgres psql -c "CREATE USER ckan_default WITH PASSWORD 'pass';"
sudo -u postgres psql -c 'CREATE DATABASE ckan_test WITH OWNER ckan_default;'

echo "Setting up Solr..."
docker run --name ckan-solr -p 8983:8983 -d ghcr.io/keitaroinc/ckan-solr-dev:2.8

echo "Initialising the database..."

cd ckan
paster --plugin=ckan db init -c test-core.ini

cd -

echo "Installing ckanext-saml2auth and its requirements..."
pip install -r requirements.txt

pip install -r dev-requirements.txt
python setup.py develop

echo "Moving test.ini into a subdir..."
mkdir subdir
mv test.ini subdir

echo "travis-build.bash is done."
