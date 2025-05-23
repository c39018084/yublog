#!/bin/bash

# Wait for database to be ready
echo "Waiting for database to be ready..."
while ! nc -z db 5432; do
  sleep 1
done
echo "Database is ready!"

# Wait for Redis to be ready
echo "Waiting for Redis to be ready..."
while ! nc -z redis 6379; do
  sleep 1
done
echo "Redis is ready!"

# Initialize database
echo "Initializing database..."
python -c "
from app import app, db
with app.app_context():
    try:
        db.create_all()
        print('Database tables created successfully')
    except Exception as e:
        print(f'Database initialization error: {e}')
"

# Start the application
echo "Starting Flask application..."
exec gunicorn --bind 0.0.0.0:5000 --workers 2 --worker-class sync --timeout 30 --keep-alive 2 --max-requests 1000 --max-requests-jitter 100 --access-logfile - --error-logfile - app:app 