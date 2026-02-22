FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        postgresql-client \
        build-essential \
        libpq-dev \
        libssl-dev \
        libffi-dev \
        gdal-bin \
        libgdal-dev \
        libproj-dev \
        libgeos-dev \
        binutils \
        curl && \
    rm -rf /var/lib/apt/lists/*

# Update pip
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install Python dependencies
COPY requirements/production.txt /app/requirements/
RUN pip install --no-cache-dir -r requirements/production.txt

# Copy project
COPY . /app/

# Create necessary directories
RUN mkdir -p /app/logs /app/media /app/staticfiles

# Set permissions
RUN chmod +x /app/manage.py

# ✅ УДАЛЕНО: RUN python manage.py collectstatic (выполняется в docker-compose command)

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health/ || exit 1

# Run the application (миграции + collectstatic + gunicorn)
CMD ["sh", "-c", "python manage.py migrate && python manage.py collectstatic --noinput && gunicorn --bind 0.0.0.0:8000 --workers 3 --timeout 120 --max-requests 1000 --max-requests-jitter 50 core.wsgi:application"]
