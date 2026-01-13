#!/bin/bash
set -e

# Check if services are running
if ! docker-compose -f docker-compose.test.yml ps | grep -q "Up"; then
    echo "Services not running. Starting them..."
    docker-compose -f docker-compose.test.yml up -d
    sleep 5
fi

# Run tests
echo "Running tests..."
docker-compose -f docker-compose.test.yml exec -T ckan-dev bash -c "
    cd /srv/app/src/ckanext-saml2auth
    pytest --ckan-ini=test.ini --cov=ckanext.saml2auth --disable-warnings ckanext/saml2auth/tests $@
" | tee test_results.txt

echo ""
echo "Test results saved to test_results.txt"
