#!/bin/bash

# YuBlog Database Reset Script (Docker Version)
# This script resets the database and applies the new schema with security features

set -e

echo "🗄️  Resetting YuBlog database (Docker)..."

# Check if database container is running
if ! docker-compose ps db | grep -q "Up"; then
    echo "❌ Database container is not running"
    echo "   Please start it with: docker-compose up -d db"
    exit 1
fi

echo "✅ Database container is running"

# Drop and recreate database
echo "🔄 Dropping and recreating database..."
docker-compose exec -T db psql -U yublog -d postgres -c "DROP DATABASE IF EXISTS yublog;"
docker-compose exec -T db psql -U yublog -d postgres -c "CREATE DATABASE yublog;"

# Ensure user has proper permissions
echo "🔐 Setting up database user permissions..."
docker-compose exec -T db psql -U yublog -d postgres -c "ALTER USER yublog WITH PASSWORD 'dev_db_password_123';"
docker-compose exec -T db psql -U yublog -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE yublog TO yublog;"

echo "✅ Database recreated"

# Apply new schema
echo "📝 Applying new database schema..."
docker-compose exec -T db psql -U yublog -d yublog < database/init.sql

echo "✅ Database schema applied successfully"

# Verify the new tables exist
echo "🔍 Verifying new security tables..."
docker-compose exec -T db psql -U yublog -d yublog -c "
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