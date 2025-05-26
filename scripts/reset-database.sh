#!/bin/bash

# YuBlog Database Reset Script
# This script resets the database and applies the new schema with security features

set -e

echo "🗄️  Resetting YuBlog database..."

# Load environment variables
if [ -f .env ]; then
    export $(grep -v '^#' .env | grep -v '^$' | xargs)
else
    echo "⚠️  .env file not found, using defaults"
fi

# Database connection details with defaults
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_NAME=${DB_NAME:-yublog}
DB_USER=${DB_USER:-yublog}
DB_PASSWORD=${DB_PASSWORD:-dev_db_password_123}

echo "📋 Database connection details:"
echo "  Host: $DB_HOST"
echo "  Port: $DB_PORT"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"

# Check if PostgreSQL is running
if ! pg_isready -h $DB_HOST -p $DB_PORT -U $DB_USER > /dev/null 2>&1; then
    echo "❌ PostgreSQL is not running or not accessible"
    echo "   Please start PostgreSQL and ensure it's accessible"
    exit 1
fi

echo "✅ PostgreSQL is running"

# Drop and recreate database
echo "🔄 Dropping and recreating database..."
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME;"
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d postgres -c "CREATE DATABASE $DB_NAME;"

echo "✅ Database recreated"

# Apply new schema
echo "📝 Applying new database schema..."
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -f database/init.sql

echo "✅ Database schema applied successfully"

# Verify the new tables exist
echo "🔍 Verifying new security tables..."
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "
SELECT 
    table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
    AND table_name IN ('device_registrations', 'users', 'credentials')
ORDER BY table_name;
"

echo ""
echo "🎉 Database reset complete!"
echo ""
echo "New security features:"
echo "  ✓ Device registration tracking (34-day cooldown)"
echo "  ✓ Admin privileges for first user"
echo "  ✓ Enhanced audit logging"
echo "  ✓ Account spam prevention"
echo ""
echo "Next steps:"
echo "1. Start the application: make up"
echo "2. Register the first user (will get admin privileges)"
echo "3. Test device registration limits"
echo "" 