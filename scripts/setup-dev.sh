#!/bin/bash

# YuBlog Development Setup Script
# This script sets up the development environment to prevent configuration errors

set -e

echo "🔧 Setting up YuBlog development environment..."

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp environment.example .env
    
    # Generate secure development secrets
    echo "🔐 Generating development secrets..."
    
    # Generate JWT secret
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || openssl rand -base64 32)
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || openssl rand -base64 32)
    
    # Update .env with development values
    sed -i.bak \
        -e "s/your-very-secure-database-password-here/dev_db_password_123/" \
        -e "s/your-very-secure-redis-password-here/dev_redis_password_456/" \
        -e "s/your-super-secret-jwt-key-change-this-in-production/$JWT_SECRET/" \
        -e "s/your-super-secret-flask-key-change-this-in-production/$SECRET_KEY/" \
        -e "s/yourdomain.com/localhost/g" \
        -e "s/Your Blog Name/YuBlog Development/" \
        -e "s/https:\/\/yourdomain.com/https:\/\/localhost/g" \
        .env
    
    rm -f .env.bak
    echo "✅ .env file created with development defaults"
else
    echo "ℹ️  .env file already exists, skipping creation"
fi

# Create SSL certificates directory if it doesn't exist
if [ ! -d "docker/nginx/ssl" ]; then
    mkdir -p docker/nginx/ssl
fi

# Create self-signed SSL certificates for development
if [ ! -f "docker/nginx/ssl/cert.pem" ] || [ ! -f "docker/nginx/ssl/key.pem" ]; then
    echo "🔒 Creating self-signed SSL certificates for development..."
    
    openssl req -x509 -newkey rsa:4096 -keyout docker/nginx/ssl/key.pem -out docker/nginx/ssl/cert.pem -days 365 -nodes -subj "/C=US/ST=Development/L=Development/O=YuBlog Dev/CN=localhost" 2>/dev/null
    
    echo "✅ SSL certificates created"
else
    echo "ℹ️  SSL certificates already exist, skipping creation"
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p docker/nginx/logs
mkdir -p backend/logs

# Set proper permissions
echo "🔐 Setting proper permissions..."
chmod 600 docker/nginx/ssl/key.pem 2>/dev/null || true
chmod 644 docker/nginx/ssl/cert.pem 2>/dev/null || true

echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "Next steps:"
echo "1. Run: docker-compose up -d"
echo "2. Wait for all services to start (check with: docker-compose ps)"
echo "3. Access the application at: https://localhost"
echo ""
echo "⚠️  NOTE: You may see SSL warnings in your browser for the self-signed certificate."
echo "   This is normal for development. Click 'Advanced' and 'Proceed to localhost'."
echo "" 