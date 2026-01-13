.PHONY: help setup test test-fast test-file shell up down restart rebuild logs clean status

# Default target
help:
	@echo "Available commands:"
	@echo "  make setup       - One-time setup (install all dependencies)"
	@echo "  make test        - Run all tests"
	@echo "  make test-fast   - Run tests, stop at first failure"
	@echo "  make test-file FILE=path/to/test.py - Run specific test file"
	@echo "  make shell       - Enter the CKAN container"
	@echo "  make up          - Start services"
	@echo "  make down        - Stop services"
	@echo "  make restart     - Restart services"
	@echo "  make rebuild     - Rebuild and restart containers"
	@echo "  make logs        - Show container logs"
	@echo "  make status      - Show service status"
	@echo "  make clean       - Stop and remove all containers/volumes"

# One-time setup
setup:
	@./setup-test-env.sh

# Run all tests
test:
	@./run-docker-tests.sh

# Run tests, stop at first failure
test-fast:
	@./run-docker-tests.sh -x

# Run specific test file
# Usage: make test-file FILE=ckanext/saml2auth/tests/test_blueprint.py
test-file:
	@if [ -z "$(FILE)" ]; then \
		echo "Error: FILE parameter required. Usage: make test-file FILE=path/to/test.py"; \
		exit 1; \
	fi
	@./run-docker-tests.sh $(FILE)

# Enter the CKAN container
shell:
	@docker-compose -f docker-compose.test.yml exec ckan-dev bash

# Start services
up:
	@docker-compose -f docker-compose.test.yml up -d
	@echo "Services started. Run 'make status' to check."

# Stop services
down:
	@docker-compose -f docker-compose.test.yml down
	@echo "Services stopped."

# Restart services
restart:
	@docker-compose -f docker-compose.test.yml restart
	@echo "Services restarted."

# Rebuild and restart containers
rebuild:
	@echo "Stopping services..."
	@docker-compose -f docker-compose.test.yml down
	@echo "Rebuilding containers..."
	@docker-compose -f docker-compose.test.yml build --no-cache
	@echo "Starting services..."
	@docker-compose -f docker-compose.test.yml up -d
	@echo "Rebuild complete. Run 'make status' to check."

# Show logs
logs:
	@docker-compose -f docker-compose.test.yml logs -f

# Show service status
status:
	@docker-compose -f docker-compose.test.yml ps

# Clean everything (removes containers and volumes)
clean:
	@docker-compose -f docker-compose.test.yml down -v
	@echo "All containers and volumes removed."
