# Land Contract Management System - Makefile
# Common commands for development and deployment

.PHONY: help install dev test deploy clean docker-build docker-up docker-down backup restore

# Default target
help:
	@echo "Land Contract Management System - Available Commands:"
	@echo ""
	@echo "Development:"
	@echo "  install      - Install all dependencies and setup development environment"
	@echo "  dev          - Start development servers"
	@echo "  test         - Run all tests"
	@echo "  lint         - Run code linting"
	@echo "  format       - Format code"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build - Build Docker images"
	@echo "  docker-up    - Start Docker containers"
	@echo "  docker-down  - Stop Docker containers"
	@echo "  docker-logs  - Show Docker logs"
	@echo ""
	@echo "Database:"
	@echo "  migrate      - Run database migrations"
	@echo "  createsuperuser - Create Django superuser"
	@echo "  backup       - Backup database"
	@echo "  restore      - Restore database from backup"
	@echo ""
	@echo "Deployment:"
	@echo "  deploy       - Deploy to production"
	@echo "  deploy-staging - Deploy to staging"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean        - Clean temporary files"
	@echo "  collectstatic - Collect static files"
	@echo "  check        - Run system health checks"

# Development setup
install:
	@echo "Setting up development environment..."
	@chmod +x scripts/setup-dev.sh
	@./scripts/setup-dev.sh

# Start development servers
dev:
	@echo "Starting development servers..."
	@echo "Starting backend server..."
	@cd backend && source venv/bin/activate && python manage.py runserver &
	@echo "Starting frontend server..."
	@cd frontend && npm start &
	@echo "Starting Celery worker..."
	@cd backend && source venv/bin/activate && celery -A core worker --loglevel=info &
	@echo "All servers started. Access at:"
	@echo "  Frontend: http://localhost:3000"
	@echo "  Backend: http://localhost:8000"
	@echo "  Admin: http://localhost:8000/admin"

# Run tests
test:
	@echo "Running backend tests..."
	@cd backend && source venv/bin/activate && python manage.py test
	@echo "Running frontend tests..."
	@cd frontend && npm test

# Run code linting
lint:
	@echo "Running backend linting..."
	@cd backend && source venv/bin/activate && flake8 . --exclude=venv,migrations
	@echo "Running frontend linting..."
	@cd frontend && npm run lint

# Format code
format:
	@echo "Formatting backend code..."
	@cd backend && source venv/bin/activate && black . --exclude=venv,migrations
	@echo "Formatting frontend code..."
	@cd frontend && npm run format

# Docker commands
docker-build:
	@echo "Building Docker images..."
	@docker-compose build

docker-up:
	@echo "Starting Docker containers..."
	@docker-compose up -d

docker-down:
	@echo "Stopping Docker containers..."
	@docker-compose down

docker-logs:
	@echo "Showing Docker logs..."
	@docker-compose logs -f

# Database commands
migrate:
	@echo "Running database migrations..."
	@cd backend && source venv/bin/activate && python manage.py migrate

createsuperuser:
	@echo "Creating Django superuser..."
	@cd backend && source venv/bin/activate && python manage.py createsuperuser

backup:
	@echo "Creating database backup..."
	@chmod +x scripts/backup.sh
	@./scripts/backup.sh

restore:
	@echo "Restoring database from backup..."
	@chmod +x scripts/restore.sh
	@./scripts/restore.sh

# Deployment commands
deploy:
	@echo "Deploying to production..."
	@chmod +x scripts/deploy.sh
	@./scripts/deploy.sh

deploy-staging:
	@echo "Deploying to staging..."
	@chmod +x scripts/deploy-staging.sh
	@./scripts/deploy-staging.sh

# Maintenance commands
clean:
	@echo "Cleaning temporary files..."
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@find . -type d -name "*.egg-info" -exec rm -rf {} +
	@cd frontend && rm -rf node_modules/.cache
	@cd backend && rm -rf .coverage htmlcov

collectstatic:
	@echo "Collecting static files..."
	@cd backend && source venv/bin/activate && python manage.py collectstatic --noinput

check:
	@echo "Running system health checks..."
	@cd backend && source venv/bin/activate && python manage.py check --deploy
	@echo "Checking database connection..."
	@cd backend && source venv/bin/activate && python manage.py dbshell --command "SELECT 1;"
	@echo "Checking Redis connection..."
	@redis-cli ping

# Development utilities
shell:
	@echo "Opening Django shell..."
	@cd backend && source venv/bin/activate && python manage.py shell

dbshell:
	@echo "Opening database shell..."
	@cd backend && source venv/bin/activate && python manage.py dbshell

# Frontend specific commands
frontend-install:
	@echo "Installing frontend dependencies..."
	@cd frontend && npm install

frontend-build:
	@echo "Building frontend for production..."
	@cd frontend && npm run build

frontend-test:
	@echo "Running frontend tests..."
	@cd frontend && npm test

# Backend specific commands
backend-install:
	@echo "Installing backend dependencies..."
	@cd backend && source venv/bin/activate && pip install -r requirements/development.txt

backend-migrate:
	@echo "Running backend migrations..."
	@cd backend && source venv/bin/activate && python manage.py migrate

backend-test:
	@echo "Running backend tests..."
	@cd backend && source venv/bin/activate && python manage.py test

# Documentation
docs:
	@echo "Generating documentation..."
	@cd backend && source venv/bin/activate && python manage.py graph_models -a -o docs/models.png
	@echo "Documentation generated in docs/ directory"

# Security
security-check:
	@echo "Running security checks..."
	@cd backend && source venv/bin/activate && pip install safety
	@cd backend && source venv/bin/activate && safety check
	@cd backend && source venv/bin/activate && bandit -r . -f json -o security-report.json

# Performance
performance-test:
	@echo "Running performance tests..."
	@cd tests/performance && python run_performance_tests.py

# Monitoring
monitoring-setup:
	@echo "Setting up monitoring..."
	@docker-compose -f docker-compose.monitoring.yml up -d

logs:
	@echo "Showing application logs..."
	@tail -f backend/logs/django.log

# Quick start for new developers
quick-start: install docker-up migrate createsuperuser
	@echo "Quick start completed!"
	@echo "Access the application at:"
	@echo "  Frontend: http://localhost:3000"
	@echo "  Backend: http://localhost:8000"
	@echo "  Admin: http://localhost:8000/admin"