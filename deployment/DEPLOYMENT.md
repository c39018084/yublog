# YuBlog Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying YuBlog, a passwordless secure blogging platform, on a self-hosted environment.

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+ or RHEL 8+ recommended)
- **CPU**: 2 cores minimum (4 cores recommended)
- **RAM**: 4GB minimum (8GB recommended)
- **Storage**: 20GB minimum (SSD recommended)
- **Network**: Public IP address with ports 80 and 443 accessible

### Required Software

- Docker Engine 20.10+
- Docker Compose 2.0+
- Git
- OpenSSL (for certificate generation)

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/c39018084/yublog.git
cd yublog
```

### 2. Configure Environment

Copy the example environment file and customize it:

```bash
cp environment.example .env
```

Edit the `.env` file with your specific configuration:

```bash
nano .env
```

**Critical Settings to Change:**

- `DB_PASSWORD`: Strong database password
- `REDIS_PASSWORD`: Strong Redis password  
- `JWT_SECRET_KEY`: Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- `SECRET_KEY`: Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- `WEBAUTHN_RP_ID`: Your domain name (e.g., `yourdomain.com`)
- `WEBAUTHN_RP_NAME`: Your blog name
- `WEBAUTHN_ORIGIN`: Your full URL (e.g., `https://yourdomain.com`)

### 3. Generate SSL Certificates

#### Option A: Self-Signed Certificates (Development/Testing)

```bash
mkdir -p docker/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout docker/nginx/ssl/key.pem \
    -out docker/nginx/ssl/cert.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

#### Option B: Let's Encrypt Certificates (Production)

```bash
# Install certbot
sudo apt update && sudo apt install certbot

# Generate certificate
sudo certbot certonly --standalone -d yourdomain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem docker/nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem docker/nginx/ssl/key.pem
sudo chown $USER:$USER docker/nginx/ssl/*.pem
```

### 4. Deploy with Docker Compose

```bash
# Start all services
docker-compose up -d

# Verify deployment
docker-compose ps
docker-compose logs -f
```

### 5. Initial Setup

1. **Access the application**: Open https://yourdomain.com in your browser
2. **Register your first user**: Use the WebAuthn registration flow with your YubiKey
3. **Create your first blog post**: Start writing!

## Detailed Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `DB_PASSWORD` | PostgreSQL password | Yes | - |
| `REDIS_PASSWORD` | Redis password | Yes | - |
| `JWT_SECRET_KEY` | JWT signing key | Yes | - |
| `SECRET_KEY` | Flask secret key | Yes | - |
| `WEBAUTHN_RP_ID` | WebAuthn relying party ID | Yes | localhost |
| `WEBAUTHN_RP_NAME` | Display name for your app | Yes | YuBlog |
| `WEBAUTHN_ORIGIN` | Full origin URL | Yes | https://localhost:3000 |
| `FLASK_ENV` | Flask environment | No | production |

### Docker Services

- **nginx**: Reverse proxy and load balancer (ports 80, 443)
- **frontend**: React application (internal port 3000)
- **backend**: Flask API server (internal port 5000)
- **db**: PostgreSQL database (internal port 5432)
- **redis**: Cache and session store (internal port 6379)
- **scheduler**: Cleanup tasks (background)

### Network Architecture

```
Internet
    ↓
┌─────────────┐
│    Nginx    │  (Port 80/443)
│ (SSL Term)  │
└─────────────┘
    ↓
┌─────────────┐
│  Frontend   │  (React SPA)
│   + API     │
└─────────────┘
    ↓
┌─────────────┐
│   Backend   │  (Flask API)
└─────────────┘
    ↓
┌─────────────┐  ┌─────────────┐
│ PostgreSQL  │  │    Redis    │
│ (Database)  │  │   (Cache)   │
└─────────────┘  └─────────────┘
```

## Security Configuration

### Firewall Setup

Configure your firewall to only allow necessary ports:

```bash
# Ubuntu/Debian with ufw
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# RHEL/CentOS with firewalld
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

### SSL/TLS Configuration

The Nginx configuration uses:
- TLS 1.2 and 1.3 only
- Strong cipher suites
- HSTS headers
- Perfect Forward Secrecy

### Database Security

- Strong passwords required
- Connection encryption enabled
- Audit logging enabled
- Row-level security policies

### Application Security

- Rate limiting on all endpoints
- Input validation and sanitization
- CSRF protection
- XSS prevention
- Comprehensive audit logging

## Monitoring and Maintenance

### Health Checks

Monitor application health:

```bash
# Check service status
docker-compose ps

# View logs
docker-compose logs -f backend
docker-compose logs -f nginx

# Health check endpoints
curl -k https://yourdomain.com/api/health
```

### Log Management

Logs are stored in:
- Nginx: `docker/nginx/logs/`
- Backend: `backend/logs/`
- Database: Docker volume
- Redis: Docker volume

### Backup Strategy

#### Database Backup

```bash
# Create backup
docker-compose exec db pg_dump -U yublog yublog > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore backup
docker-compose exec -T db psql -U yublog yublog < backup_file.sql
```

#### Full System Backup

```bash
# Stop services
docker-compose down

# Backup volumes
docker run --rm -v yublog_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_backup.tar.gz -C /data .
docker run --rm -v yublog_redis_data:/data -v $(pwd):/backup alpine tar czf /backup/redis_backup.tar.gz -C /data .

# Backup configuration
tar czf config_backup.tar.gz docker/ .env

# Start services
docker-compose up -d
```

### Updates

#### Application Updates

```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

#### Security Updates

```bash
# Update base images
docker-compose pull
docker-compose up -d
```

## Troubleshooting

### Common Issues

#### 1. SSL Certificate Issues

**Symptoms**: Browser SSL warnings, connection refused

**Solutions**:
```bash
# Check certificate validity
openssl x509 -in docker/nginx/ssl/cert.pem -text -noout

# Regenerate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout docker/nginx/ssl/key.pem \
    -out docker/nginx/ssl/cert.pem
```

#### 2. Database Connection Issues

**Symptoms**: Backend cannot connect to database

**Solutions**:
```bash
# Check database logs
docker-compose logs db

# Verify database is running
docker-compose exec db pg_isready -U yublog

# Reset database password
docker-compose down
docker volume rm yublog_postgres_data
docker-compose up -d
```

#### 3. WebAuthn Issues

**Symptoms**: YubiKey registration/authentication fails

**Solutions**:
- Verify `WEBAUTHN_RP_ID` matches your domain
- Ensure `WEBAUTHN_ORIGIN` is correct
- Check browser console for errors
- Use HTTPS (required for WebAuthn)

#### 4. Performance Issues

**Symptoms**: Slow response times, high resource usage

**Solutions**:
```bash
# Check resource usage
docker stats

# Scale backend services
docker-compose up -d --scale backend=3

# Check nginx logs for bottlenecks
docker-compose logs nginx | grep -E "(50[0-9]|upstream)"
```

### Logs Analysis

#### Backend Logs
```bash
# View real-time logs
docker-compose logs -f backend

# Search for errors
docker-compose logs backend | grep ERROR

# Authentication events
docker-compose logs backend | grep "login_attempt\|login_success"
```

#### Nginx Logs
```bash
# Access logs
docker-compose exec nginx tail -f /var/log/nginx/access.log

# Error logs
docker-compose exec nginx tail -f /var/log/nginx/error.log

# Rate limiting events
docker-compose logs nginx | grep "limiting requests"
```

## Advanced Configuration

### High Availability Setup

For production environments requiring high availability:

#### Load Balancer Configuration
```yaml
# Add to docker-compose.yml
services:
  backend-1:
    <<: *backend-service
  backend-2:
    <<: *backend-service
  backend-3:
    <<: *backend-service
```

#### Database Clustering
- Configure PostgreSQL streaming replication
- Use pgpool-II for connection pooling
- Implement automated failover

### Performance Optimization

#### Database Tuning
```sql
-- Optimize PostgreSQL settings
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
SELECT pg_reload_conf();
```

#### Redis Optimization
```bash
# Add to Redis configuration
maxmemory 512mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

### Security Hardening

#### Additional Nginx Security
```nginx
# Add to nginx configuration
add_header X-Permitted-Cross-Domain-Policies none always;
add_header X-Robots-Tag none always;
add_header Expect-CT "enforce, max-age=86400" always;
```

#### Database Hardening
```sql
-- Create read-only user for monitoring
CREATE USER monitor WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE yublog TO monitor;
GRANT USAGE ON SCHEMA public TO monitor;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO monitor;
```

## Migration from Other Platforms

### From WordPress
1. Export content using WordPress export tool
2. Convert to YuBlog format using provided migration script
3. Import using the bulk import API

### From Ghost
1. Export Ghost content as JSON
2. Use the Ghost migration script in `scripts/migrate-ghost.py`
3. Verify imported content

## Development Setup

For development environments:

```bash
# Use development environment
cp environment.example .env.dev
export FLASK_ENV=development

# Start development services
docker-compose -f docker-compose.dev.yml up -d

# Enable hot reloading
docker-compose exec backend python app_complete.py
```

## Support and Community

- **Documentation**: See `docs/` directory
- **Issues**: Report on GitHub Issues
- **Security**: Contact security@yourdomain.com
- **Community**: Join our discussion forum

## License

YuBlog is released under the MIT License. See LICENSE file for details. 