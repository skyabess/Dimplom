FROM python:3.11-slim

# Устанавливаем системные зависимости с фиксом apt
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    postgresql-client \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Копируем requirements и устанавливаем зависимости
COPY requirements/production.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код
COPY . .

# Собираем статику
RUN python manage.py collectstatic --noinput || true

EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120", "core.wsgi:application"]