#!/bin/bash
set -e

echo "=== Setting up test environment in Docker ==="

# Start services
echo "Starting services..."
docker-compose -f docker-compose.test.yml up -d

# Wait for services to be ready
echo "Waiting for services to be ready..."
sleep 10

# Install Python dependencies and extension
echo "Installing Python dependencies..."
docker-compose -f docker-compose.test.yml exec -T ckan-dev bash -c "
    cd /srv/app/src/ckanext-saml2auth

    # Install system dependencies (xmlsec1 is required for pysaml2)
    apt-get update && apt-get install -y xmlsec1

    # Install Python requirements
    pip install -r requirements.txt
    pip install -r dev-requirements.txt

    # Install extension in development mode
    pip install -e .

    # Replace default path to CKAN core config file with the one on the container
    sed -i -e 's/use = config:.*/use = config:\/srv\/app\/src\/ckan\/test-core.ini/' test.ini
"

# Configure git
echo "Configuring git..."
docker-compose -f docker-compose.test.yml exec -T ckan-dev bash -c "
    # Configure git to trust this directory (mounted volume)
    git config --global --add safe.directory /srv/app/src/ckanext-saml2auth
    git config --global user.email 'test@example.com'
    git config --global user.name 'Test User'
"

# Initialize CKAN database
echo "Initializing CKAN database..."
docker-compose -f docker-compose.test.yml exec -T ckan-dev bash -c "
    cd /srv/app/src/ckanext-saml2auth
    ckan -c test.ini db init
"

echo ""
echo "=== Setup complete! ==="
echo ""
echo "To run tests, use:"
echo "  make test           # Run all tests"
echo "  make test-fast      # Run tests, stop at first failure"
echo "  ./run-docker-tests.sh"
echo ""
echo "To enter the container:"
echo "  make shell"
echo "  docker-compose -f docker-compose.test.yml exec ckan-dev bash"
echo ""
echo "To stop services:"
echo "  make down"
echo "  docker-compose -f docker-compose.test.yml down"
echo ""
