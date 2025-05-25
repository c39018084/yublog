# Docker Commands Reference for YuBlog

This document contains all the Docker and Docker Compose commands you need to work with the YuBlog project.

## Quick Start Commands

### Start the Application
```bash
# Start all services with the full setup (includes nginx, worker, scheduler)
docker-compose up -d

# Start with the simple setup (development mode with exposed ports)
docker-compose -f docker-compose.simple.yml up -d

# Start in foreground to see logs
docker-compose up
```

### Stop the Application
```bash
# Stop all services
docker-compose down

# Stop and remove volumes (WARNING: This deletes your data!)
docker-compose down -v

# Stop simple setup
docker-compose -f docker-compose.simple.yml down
```

## Building and Rebuilding

### Build Images
```bash
# Build all images
docker-compose build

# Build specific service
docker-compose build backend
docker-compose build frontend

# Build without cache (force rebuild)
docker-compose build --no-cache

# Pull latest base images and rebuild
docker-compose build --pull
```

## Managing Services

### Start/Stop Individual Services
```bash
# Start specific services
docker-compose start db redis
docker-compose start backend frontend

# Stop specific services
docker-compose stop backend
docker-compose stop frontend

# Restart services
docker-compose restart backend
docker-compose restart nginx
```

### Scale Services
```bash
# Scale backend to 3 instances
docker-compose up -d --scale backend=3

# Scale worker processes
docker-compose up -d --scale worker=2
```

## Logs and Monitoring

### View Logs
```bash
# View all logs
docker-compose logs

# Follow logs in real-time
docker-compose logs -f

# View logs for specific service
docker-compose logs backend
docker-compose logs frontend
docker-compose logs db

# Follow logs for specific service
docker-compose logs -f backend

# View last 100 lines
docker-compose logs --tail=100
```

### Check Service Status
```bash
# List running containers
docker-compose ps

# Check detailed status
docker-compose ps -a

# View resource usage
docker stats
```

## Database Operations

### Database Access
```bash
# Connect to PostgreSQL database
docker-compose exec db psql -U yublog -d yublog

# Run SQL file
docker-compose exec db psql -U yublog -d yublog -f /docker-entrypoint-initdb.d/init.sql

# Backup database
docker-compose exec db pg_dump -U yublog yublog > backup.sql

# Restore database
docker-compose exec -T db psql -U yublog -d yublog < backup.sql
```

### Redis Access
```bash
# Connect to Redis CLI
docker-compose exec redis redis-cli -a redis123

# Monitor Redis
docker-compose exec redis redis-cli -a redis123 monitor

# Get Redis info
docker-compose exec redis redis-cli -a redis123 info
```

## Development Commands

### Execute Commands in Containers
```bash
# Open bash in backend container
docker-compose exec backend bash

# Run Flask commands
docker-compose exec backend flask db migrate
docker-compose exec backend flask db upgrade
docker-compose exec backend flask cleanup-sessions

# Install new Python packages
docker-compose exec backend pip install package-name

# Run tests
docker-compose exec backend pytest
docker-compose exec backend python -m pytest tests/
```

### Frontend Development
```bash
# Open bash in frontend container
docker-compose exec frontend sh

# Install new npm packages
docker-compose exec frontend npm install package-name

# Run npm commands
docker-compose exec frontend npm run build
docker-compose exec frontend npm test
```

## Debugging and Troubleshooting

### Health Checks
```bash
# Check service health
docker-compose ps

# View health check logs
docker inspect yublog_backend --format='{{json .State.Health}}'
docker inspect yublog_db --format='{{json .State.Health}}'
```

### Network Debugging
```bash
# List Docker networks
docker network ls

# Inspect network
docker network inspect yublog_frontend
docker network inspect yublog_backend

# Test connectivity between containers
docker-compose exec backend ping db
docker-compose exec frontend ping backend
```

### Volume Management
```bash
# List volumes
docker volume ls

# Inspect volume
docker volume inspect yublog_postgres_data
docker volume inspect yublog_redis_data

# Remove unused volumes (be careful!)
docker volume prune
```

## Environment and Configuration

### Environment Variables
```bash
# Use custom environment file
docker-compose --env-file .env.production up -d

# Override environment variables
DB_PASSWORD=newpassword docker-compose up -d

# Set environment for specific service
docker-compose exec -e FLASK_ENV=development backend flask run
```

### Configuration Files
```bash
# Reload nginx configuration
docker-compose exec nginx nginx -s reload

# Test nginx configuration
docker-compose exec nginx nginx -t

# View current nginx config
docker-compose exec nginx cat /etc/nginx/nginx.conf
```

## Data Management

### Backup Data
```bash
# Backup PostgreSQL data
docker run --rm -v yublog_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_backup.tar.gz -C /data .

# Backup Redis data
docker run --rm -v yublog_redis_data:/data -v $(pwd):/backup alpine tar czf /backup/redis_backup.tar.gz -C /data .
```

### Restore Data
```bash
# Restore PostgreSQL data
docker run --rm -v yublog_postgres_data:/data -v $(pwd):/backup alpine tar xzf /backup/postgres_backup.tar.gz -C /data

# Restore Redis data
docker run --rm -v yublog_redis_data:/data -v $(pwd):/backup alpine tar xzf /backup/redis_backup.tar.gz -C /data
```

## Cleanup Commands

### Remove Everything
```bash
# Stop and remove containers, networks
docker-compose down

# Remove containers, networks, and volumes
docker-compose down -v

# Remove everything including images
docker-compose down -v --rmi all

# Remove orphaned containers
docker-compose down --remove-orphans
```

### Clean Docker System
```bash
# Remove unused containers, networks, images
docker system prune

# Remove everything (including volumes)
docker system prune -a --volumes

# Remove only unused images
docker image prune

# Remove only unused volumes
docker volume prune
```

## Production Commands

### Production Deployment
```bash
# Deploy with production settings
docker-compose -f docker-compose.yml up -d

# Deploy specific services only
docker-compose up -d db redis backend frontend nginx

# Deploy without worker services
docker-compose up -d db redis backend frontend nginx scheduler
```

### Update Application
```bash
# Pull latest images and restart
docker-compose pull
docker-compose up -d

# Rebuild and restart specific service
docker-compose build backend
docker-compose up -d backend

# Rolling update (zero downtime)
docker-compose up -d --scale backend=2 backend
docker-compose stop old_backend_container
```

## Useful Aliases

Add these to your `.bashrc` or `.zshrc` for faster commands:

```bash
# Docker Compose shortcuts
alias dcu='docker-compose up -d'
alias dcd='docker-compose down'
alias dcl='docker-compose logs -f'
alias dcp='docker-compose ps'
alias dcb='docker-compose build'

# YuBlog specific
alias yublog-start='docker-compose up -d'
alias yublog-stop='docker-compose down'
alias yublog-logs='docker-compose logs -f'
alias yublog-simple='docker-compose -f docker-compose.simple.yml up -d'
```

## URLs and Ports

When running the application:

### Full Setup (docker-compose.yml)
- **Frontend**: http://localhost (through nginx)
- **Backend API**: http://localhost/api (through nginx)
- **Nginx**: http://localhost:80, https://localhost:443

### Simple Setup (docker-compose.simple.yml)
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000
- **Database**: localhost:5432
- **Redis**: localhost:6379

## Common Issues and Solutions

### Port Already in Use
```bash
# Find what's using the port
sudo netstat -tulpn | grep :3000
sudo lsof -i :5000

# Stop conflicting services
sudo systemctl stop nginx
sudo systemctl stop postgresql
```

### Permission Issues
```bash
# Fix file permissions
sudo chown -R $USER:$USER ./logs
sudo chmod -R 755 ./docker/nginx

# Fix volume permissions
docker-compose exec backend chown -R app:app /app/logs
```

### Database Connection Issues
```bash
# Check database is ready
docker-compose exec db pg_isready -U yublog

# Reset database
docker-compose down -v
docker-compose up -d db
# Wait for db to be ready, then start other services
docker-compose up -d
``` 