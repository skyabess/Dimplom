#!/bin/bash

# Land Contract System Deployment Script
# This script deploys the application to production

set -e

# Configuration
PROJECT_NAME="land-contract"
BACKUP_DIR="/var/backups/$PROJECT_NAME"
LOG_FILE="/var/log/$PROJECT_NAME-deploy.log"
DATE=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "${RED}ERROR: $1${NC}"
    exit 1
}

# Success message
success() {
    log "${GREEN}SUCCESS: $1${NC}"
}

# Warning message
warning() {
    log "${YELLOW}WARNING: $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error_exit "This script must be run as root"
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Function to backup database
backup_database() {
    log "Creating database backup..."
    
    # Get database credentials from environment
    DB_HOST=${DB_HOST:-localhost}
    DB_NAME=${DB_NAME:-land_contract_db}
    DB_USER=${DB_USER:-postgres}
    
    # Create backup
    pg_dump -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" | gzip > "$BACKUP_DIR/db_backup_$DATE.sql.gz"
    
    if [ $? -eq 0 ]; then
        success "Database backup created: $BACKUP_DIR/db_backup_$DATE.sql.gz"
    else
        error_exit "Failed to create database backup"
    fi
}

# Function to backup media files
backup_media() {
    log "Creating media files backup..."
    
    MEDIA_DIR="/var/www/$PROJECT_NAME/media"
    if [ -d "$MEDIA_DIR" ]; then
        tar -czf "$BACKUP_DIR/media_backup_$DATE.tar.gz" -C "$(dirname "$MEDIA_DIR")" "$(basename "$MEDIA_DIR")"
        success "Media files backup created: $BACKUP_DIR/media_backup_$DATE.tar.gz"
    else
        warning "Media directory not found, skipping media backup"
    fi
}

# Function to update application code
update_code() {
    log "Updating application code..."
    
    # Navigate to project directory
    cd "/var/www/$PROJECT_NAME" || error_exit "Project directory not found"
    
    # Pull latest changes
    git pull origin main || error_exit "Failed to pull latest changes"
    
    # Install/update Python dependencies
    pip install -r backend/requirements/production.txt || error_exit "Failed to install Python dependencies"
    
    # Install/update Node.js dependencies
    cd frontend || error_exit "Frontend directory not found"
    npm ci || error_exit "Failed to install Node.js dependencies"
    
    success "Application code updated"
}

# Function to run database migrations
run_migrations() {
    log "Running database migrations..."
    
    cd "/var/www/$PROJECT_NAME/backend" || error_exit "Backend directory not found"
    
    python manage.py migrate || error_exit "Failed to run database migrations"
    
    success "Database migrations completed"
}

# Function to collect static files
collect_static() {
    log "Collecting static files..."
    
    cd "/var/www/$PROJECT_NAME/backend" || error_exit "Backend directory not found"
    
    python manage.py collectstatic --noinput || error_exit "Failed to collect static files"
    
    success "Static files collected"
}

# Function to build frontend
build_frontend() {
    log "Building frontend..."
    
    cd "/var/www/$PROJECT_NAME/frontend" || error_exit "Frontend directory not found"
    
    npm run build || error_exit "Failed to build frontend"
    
    success "Frontend built successfully"
}

# Function to restart services
restart_services() {
    log "Restarting services..."
    
    # Restart Gunicorn
    systemctl restart gunicorn || error_exit "Failed to restart Gunicorn"
    
    # Restart Celery worker
    systemctl restart celery-worker || error_exit "Failed to restart Celery worker"
    
    # Restart Celery beat
    systemctl restart celery-beat || error_exit "Failed to restart Celery beat"
    
    # Restart Nginx
    systemctl reload nginx || error_exit "Failed to reload Nginx"
    
    success "Services restarted"
}

# Function to health check
health_check() {
    log "Performing health check..."
    
    # Check if backend is responding
    if curl -f -s http://localhost:8000/api/health/ > /dev/null; then
        success "Backend health check passed"
    else
        error_exit "Backend health check failed"
    fi
    
    # Check if frontend is responding
    if curl -f -s http://localhost:3000/ > /dev/null; then
        success "Frontend health check passed"
    else
        warning "Frontend health check failed (may be starting up)"
    fi
}

# Function to cleanup old backups
cleanup_backups() {
    log "Cleaning up old backups..."
    
    # Keep only last 7 days of backups
    find "$BACKUP_DIR" -name "*.gz" -mtime +7 -delete
    
    success "Old backups cleaned up"
}

# Main deployment process
main() {
    log "Starting deployment process..."
    
    # Pre-deployment checks
    backup_database
    backup_media
    
    # Update application
    update_code
    run_migrations
    collect_static
    build_frontend
    
    # Restart services
    restart_services
    
    # Post-deployment checks
    sleep 10  # Give services time to start
    health_check
    
    # Cleanup
    cleanup_backups
    
    success "Deployment completed successfully!"
}

# Run main function
main "$@"