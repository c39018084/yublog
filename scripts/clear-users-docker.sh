#!/bin/bash

# YuBlog Clear Users Script (Docker Version)
# This script only clears user data from the database while preserving the schema

set -e

echo "🧹 Clearing user data from YuBlog database (Docker)..."

# Check if database container is running
if ! docker-compose ps db | grep -q "Up"; then
    echo "❌ Database container is not running"
    echo "   Please start it with: docker-compose up -d db"
    exit 1
fi

echo "✅ Database container is running"

# Clear user-related data only (preserves schema)
echo "🗑️  Clearing user data tables..."
docker-compose exec -T db psql -U yublog -d yublog -c "
BEGIN;
DELETE FROM credentials;
DELETE FROM sessions;
DELETE FROM users;
DELETE FROM device_registrations;
DELETE FROM audit_logs;
COMMIT;
"

echo "✅ User data cleared successfully"

# Show remaining table structure
echo "🔍 Verifying database schema is preserved..."
docker-compose exec -T db psql -U yublog -d yublog -c "
SELECT 
    table_name,
    (SELECT count(*) FROM information_schema.columns WHERE table_name = t.table_name) as column_count
FROM information_schema.tables t
WHERE table_schema = 'public' 
ORDER BY table_name;
"

echo ""
echo "🎉 User data cleared complete!"
echo ""
echo "Database preserved:"
echo "  ✓ All table schemas intact"
echo "  ✓ All constraints and indexes preserved"
echo "  ✓ Only user data removed"
echo ""
echo "Next steps:"
echo "1. Register a new first user (will get admin privileges)"
echo "2. Test your YubiKeys without worrying about slot limits"
echo "3. All device registrations reset for fresh testing"
echo "" 