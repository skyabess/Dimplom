#!/bin/bash

# Land Contract System Development Setup Script
# This script sets up the development environment

set -e

# Configuration
PROJECT_NAME="land-contract"
PYTHON_VERSION="3.11"
NODE_VERSION="18"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}$(date '+%Y-%m-%d %H:%M:%S') - $1${NC}"
}

# Error handling
error_exit() {
    echo -e "${RED}ERROR: $1${NC}"
    exit 1
}

# Success message
success() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
}

# Warning message
warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install system dependencies
install_system_deps() {
    log "Installing system dependencies..."
    
    # Check OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command_exists apt-get; then
            sudo apt-get update
            sudo apt-get install -y \
                postgresql postgresql-contrib postgis \
                redis-server \
                python3 python3-pip python3-venv \
                nodejs npm \
                git curl wget \
                build-essential libpq-dev \
                gdal-bin libgdal-dev \
                libproj-dev libgeos-dev
        elif command_exists yum; then
            sudo yum update -y
            sudo yum install -y \
                postgresql-server postgresql-contrib postgis \
                redis \
                python3 python3-pip \
                nodejs npm \
                git curl wget \
                gcc gcc-c++ make \
                postgresql-devel \
                gdal gdal-devel \
                proj proj-devel \
                geos geos-devel
        else
            error_exit "Unsupported Linux distribution"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command_exists brew; then
            brew update
            brew install \
                postgresql postgis \
                redis \
                python@3.11 \
                node@18 \
                git \
                gdal
        else
            error_exit "Homebrew not found. Please install Homebrew first."
        fi
    else
        error_exit "Unsupported operating system"
    fi
    
    success "System dependencies installed"
}

# Function to setup Python virtual environment
setup_python_env() {
    log "Setting up Python virtual environment..."
    
    # Create virtual environment
    cd backend || error_exit "Backend directory not found"
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        success "Python virtual environment created"
    else
        warning "Python virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install Python dependencies
    pip install -r requirements/development.txt
    
    success "Python environment setup completed"
}

# Function to setup Node.js environment
setup_node_env() {
    log "Setting up Node.js environment..."
    
    cd ../frontend || error_exit "Frontend directory not found"
    
    # Install Node.js dependencies
    npm install
    
    success "Node.js environment setup completed"
}

# Function to setup PostgreSQL
setup_postgresql() {
    log "Setting up PostgreSQL..."
    
    # Start PostgreSQL service
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists systemctl; then
            sudo systemctl start postgresql
            sudo systemctl enable postgresql
        elif command_exists service; then
            sudo service postgresql start
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew services start postgresql
    fi
    
    # Create database and user
    sudo -u postgres psql -c "CREATE DATABASE land_contract_dev;" || warning "Database may already exist"
    sudo -u postgres psql -c "CREATE USER land_contract WITH PASSWORD 'password';" || warning "User may already exist"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE land_contract_dev TO land_contract;" || warning "Permissions may already be set"
    sudo -u postgres psql -d land_contract_dev -c "CREATE EXTENSION IF NOT EXISTS postgis;" || warning "PostGIS extension may already exist"
    
    success "PostgreSQL setup completed"
}

# Function to setup Redis
setup_redis() {
    log "Setting up Redis..."
    
    # Start Redis service
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists systemctl; then
            sudo systemctl start redis
            sudo systemctl enable redis
        elif command_exists service; then
            sudo service redis start
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew services start redis
    fi
    
    success "Redis setup completed"
}

# Function to setup environment variables
setup_env_vars() {
    log "Setting up environment variables..."
    
    cd .. || error_exit "Project root directory not found"
    
    # Copy environment file if it doesn't exist
    if [ ! -f ".env" ]; then
        cp .env.example .env
        success "Environment file created from example"
    else
        warning "Environment file already exists"
    fi
    
    # Generate secret key
    if ! grep -q "SECRET_KEY=" .env || grep -q "your-secret-key-here" .env; then
        SECRET_KEY=$(python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')
        sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
        success "Secret key generated"
    fi
    
    success "Environment variables setup completed"
}

# Function to run database migrations
run_migrations() {
    log "Running database migrations..."
    
    cd backend || error_exit "Backend directory not found"
    source venv/bin/activate
    
    python manage.py migrate
    
    success "Database migrations completed"
}

# Function to create superuser
create_superuser() {
    log "Creating superuser..."
    
    cd backend || error_exit "Backend directory not found"
    source venv/bin/activate
    
    echo "Creating Django superuser..."
    python manage.py createsuperuser
    
    success "Superuser created"
}

# Function to load initial data
load_initial_data() {
    log "Loading initial data..."
    
    cd backend || error_exit "Backend directory not found"
    source venv/bin/activate
    
    # Load fixtures if they exist
    if [ -d "fixtures" ]; then
        for fixture in fixtures/*.json; do
            if [ -f "$fixture" ]; then
                python manage.py loaddata "$fixture"
            fi
        done
        success "Initial data loaded"
    else
        warning "No fixtures found"
    fi
}

# Function to setup development servers
setup_dev_servers() {
    log "Setting up development servers..."
    
    # Create systemd service files for development
    if command_exists systemctl; then
        # Gunicorn service
        sudo tee /etc/systemd/system/land-contract-backend.service > /dev/null <<EOF
[Unit]
Description=Land Contract Backend
After=network.target

[Service]
Type=exec
User=$USER
WorkingDirectory=$(pwd)/backend
Environment=PATH=$(pwd)/backend/venv/bin
ExecStart=$(pwd)/backend/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 3 core.wsgi:application
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        
        # Celery worker service
        sudo tee /etc/systemd/system/land-contract-celery.service > /dev/null <<EOF
[Unit]
Description=Land Contract Celery Worker
After=network.target

[Service]
Type=exec
User=$USER
WorkingDirectory=$(pwd)/backend
Environment=PATH=$(pwd)/backend/venv/bin
ExecStart=$(pwd)/backend/venv/bin/celery -A core worker --loglevel=info
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        
        success "Development service files created"
    fi
}

# Function to provide next steps
next_steps() {
    log "Development environment setup completed!"
    echo
    echo -e "${GREEN}Next steps:${NC}"
    echo "1. Activate Python virtual environment:"
    echo "   cd backend && source venv/bin/activate"
    echo
    echo "2. Start the backend development server:"
    echo "   python manage.py runserver"
    echo
    echo "3. In another terminal, start the frontend development server:"
    echo "   cd frontend && npm start"
    echo
    echo "4. In another terminal, start Celery worker:"
    echo "   cd backend && source venv/bin/activate && celery -A core worker --loglevel=info"
    echo
    echo "5. Access the application:"
    echo "   Frontend: http://localhost:3000"
    echo "   Backend API: http://localhost:8000/api"
    echo "   Admin panel: http://localhost:8000/admin"
    echo "   API documentation: http://localhost:8000/api/docs/"
    echo
    echo -e "${YELLOW}Note: Make sure PostgreSQL and Redis are running before starting the servers.${NC}"
}

# Main setup process
main() {
    log "Starting development environment setup..."
    
    # Check if we're in the right directory
    if [ ! -f "README.md" ]; then
        error_exit "Please run this script from the project root directory"
    fi
    
    # Install dependencies
    install_system_deps
    
    # Setup environments
    setup_python_env
    setup_node_env
    
    # Setup services
    setup_postgresql
    setup_redis
    
    # Setup configuration
    setup_env_vars
    
    # Setup database
    run_migrations
    load_initial_data
    
    # Setup development servers
    setup_dev_servers
    
    # Create superuser (optional)
    read -p "Do you want to create a Django superuser? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        create_superuser
    fi
    
    # Show next steps
    next_steps
}

# Run main function
main "$@"