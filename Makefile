# YuBlog Development Makefile
.PHONY: help setup build up down clean logs restart rebuild

# Default target
help:
	@echo "YuBlog Development Commands:"
	@echo ""
	@echo "  setup     - Set up development environment (.env, SSL certs)"
	@echo "  build     - Build all Docker images"
	@echo "  up        - Start all services"
	@echo "  down      - Stop all services"
	@echo "  restart   - Restart all services"
	@echo "  rebuild   - Rebuild and restart all services"
	@echo "  clean     - Clean up containers, images, and volumes"
	@echo "  logs      - Show logs from all services"
	@echo "  logs-f    - Follow logs from all services"
	@echo ""

# Set up development environment
setup:
	@echo "Setting up development environment..."
	@chmod +x scripts/setup-dev.sh
	@./scripts/setup-dev.sh

# Build all images
build:
	@echo "Building Docker images..."
	docker-compose build

# Start services
up: setup
	@echo "Starting YuBlog services..."
	docker-compose up -d

# Stop services
down:
	@echo "Stopping YuBlog services..."
	docker-compose down

# Restart services
restart:
	@echo "Restarting YuBlog services..."
	docker-compose restart

# Rebuild and restart
rebuild:
	@echo "Rebuilding and restarting YuBlog services..."
	docker-compose down
	docker-compose build --no-cache
	docker-compose up -d

# Clean up everything
clean:
	@echo "Cleaning up Docker resources..."
	docker-compose down -v --remove-orphans
	docker system prune -f
	docker volume prune -f

# Show logs
logs:
	docker-compose logs

# Follow logs
logs-f:
	docker-compose logs -f

# Development shortcuts
dev: up
prod: setup build up 