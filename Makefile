# YuBlog Development Makefile
.PHONY: help setup up down rebuild logs clean status dev-restart dev-rebuild dev-clean dev-logs

# Default target
help:
	@echo "YuBlog Development Commands:"
	@echo ""
	@echo "Setup & Basic Operations:"
	@echo "  make setup      - Set up development environment (creates .env, SSL certs, etc.)"
	@echo "  make up         - Start all services"
	@echo "  make down       - Stop all services"
	@echo "  make status     - Show service status"
	@echo ""
	@echo "Development Workflow (USE THESE FOR CODE CHANGES):"
	@echo "  make dev-restart - Quick restart with code refresh (recommended for most changes)"
	@echo "  make dev-rebuild - Full rebuild with cache clearing (use when deps change)"
	@echo "  make dev-clean   - Nuclear option: clean everything and rebuild"
	@echo ""
	@echo "Debugging:"
	@echo "  make logs       - Show service logs"
	@echo "  make dev-logs   - Show backend logs in real-time"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean      - Clean up Docker resources"

# Set up development environment
setup:
	@echo "Setting up YuBlog development environment..."
	@if [ ! -f .env ]; then \
		echo "Creating .env file from environment.example..."; \
		cp environment.example .env; \
		echo "⚠️  Please edit .env with your own secure values!"; \
	fi
	@if [ ! -f docker/ssl/cert.pem ]; then \
		echo "Creating SSL certificates..."; \
		mkdir -p docker/ssl; \
		openssl req -x509 -newkey rsa:4096 -keyout docker/ssl/key.pem -out docker/ssl/cert.pem -days 365 -nodes -subj "/C=US/ST=Dev/L=Dev/O=YuBlog/CN=localhost"; \
		echo "SSL certificates created."; \
	fi
	@echo "✅ Development environment ready!"
	@echo "Run 'make up' to start services"

# Start services
up:
	docker-compose up -d

# Stop services
down:
	docker-compose down

# Show service status
status:
	@echo "=== Docker Compose Services ==="
	docker-compose ps
	@echo ""
	@echo "=== Container Resource Usage ==="
	docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# Show logs
logs:
	docker-compose logs --tail=50

# Clean up Docker resources
clean:
	@echo "Cleaning up Docker resources..."
	docker-compose down -v --remove-orphans
	docker system prune -f
	docker volume prune -f
	@echo "✅ Cleanup complete"

# === DEVELOPMENT WORKFLOW COMMANDS ===

# Quick restart with code refresh (recommended for most code changes)
dev-restart:
	@echo "🔄 Quick restart with code refresh..."
	@echo "Stopping services..."
	docker-compose down
	@echo "Removing backend container to force rebuild..."
	docker rmi yublog-backend-js:latest 2>/dev/null || true
	@echo "Starting services with fresh build..."
	docker-compose up -d --build
	@echo "✅ Services restarted with fresh code"
	@echo "📋 Checking status..."
	@sleep 3
	docker-compose ps
	@echo ""
	@echo "📝 Backend logs (last 20 lines):"
	docker-compose logs --tail=20 backend-js

# Full rebuild with cache clearing (use when dependencies change)
dev-rebuild:
	@echo "🔨 Full rebuild with cache clearing..."
	@echo "Stopping all services..."
	docker-compose down -v
	@echo "Removing all project images..."
	docker rmi yublog-backend-js:latest 2>/dev/null || true
	docker rmi yublog-frontend:latest 2>/dev/null || true
	@echo "Clearing Docker build cache..."
	docker builder prune -f
	@echo "Building and starting with no cache..."
	docker-compose build --no-cache
	docker-compose up -d
	@echo "✅ Full rebuild complete"
	@echo "📋 Checking status..."
	@sleep 5
	docker-compose ps
	@echo ""
	@echo "📝 Backend logs (last 30 lines):"
	docker-compose logs --tail=30 backend-js

# Nuclear option: clean everything and rebuild
dev-clean:
	@echo "💥 Nuclear clean and rebuild..."
	@echo "Stopping all services..."
	docker-compose down -v --remove-orphans
	@echo "Removing ALL project-related images..."
	docker rmi yublog-backend-js:latest 2>/dev/null || true
	docker rmi yublog-frontend:latest 2>/dev/null || true
	docker rmi postgres:15 2>/dev/null || true
	docker rmi redis:7-alpine 2>/dev/null || true
	docker rmi nginx:alpine 2>/dev/null || true
	@echo "Cleaning Docker system..."
	docker system prune -af
	docker volume prune -f
	docker builder prune -af
	@echo "Rebuilding everything from scratch..."
	docker-compose build --no-cache --pull
	docker-compose up -d
	@echo "✅ Nuclear rebuild complete"
	@echo "📋 Final status check..."
	@sleep 5
	docker-compose ps
	@echo ""
	@echo "📝 All service logs:"
	docker-compose logs --tail=20

# Show backend logs in real-time
dev-logs:
	@echo "📝 Showing backend logs in real-time (Ctrl+C to exit)..."
	docker-compose logs -f backend-js

# Legacy aliases for backward compatibility
rebuild: dev-rebuild 