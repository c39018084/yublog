#!/bin/bash

# YuBlog Quick Development Script
# Usage: ./dev.sh [command]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi
}

# Function to restart with code refresh (most common use case)
restart_fresh() {
    print_status "🔄 Restarting with fresh code..."
    
    # Stop services
    print_status "Stopping services..."
    docker-compose down
    
    # Remove backend image to force rebuild
    print_status "Removing backend image to force rebuild..."
    docker rmi yublog-backend-js:latest 2>/dev/null || true
    
    # Start with build
    print_status "Starting services with fresh build..."
    docker-compose up -d --build
    
    # Wait a moment for services to start
    sleep 3
    
    # Show status
    print_success "Services restarted with fresh code!"
    echo ""
    print_status "📋 Service Status:"
    docker-compose ps
    
    echo ""
    print_status "📝 Backend logs (last 20 lines):"
    docker-compose logs --tail=20 backend-js
    
    echo ""
    print_success "✅ Ready for testing!"
    print_status "Frontend: https://localhost"
    print_status "API: https://localhost/api/health"
}

# Function for full rebuild
full_rebuild() {
    print_status "🔨 Full rebuild with cache clearing..."
    
    # Stop all services
    print_status "Stopping all services..."
    docker-compose down -v
    
    # Remove project images
    print_status "Removing project images..."
    docker rmi yublog-backend-js:latest 2>/dev/null || true
    docker rmi yublog-frontend:latest 2>/dev/null || true
    
    # Clear build cache
    print_status "Clearing Docker build cache..."
    docker builder prune -f
    
    # Build and start
    print_status "Building and starting with no cache..."
    docker-compose build --no-cache
    docker-compose up -d
    
    # Wait for services
    sleep 5
    
    print_success "✅ Full rebuild complete!"
    docker-compose ps
}

# Function to show logs
show_logs() {
    print_status "📝 Showing backend logs in real-time (Ctrl+C to exit)..."
    docker-compose logs -f backend-js
}

# Function to show status
show_status() {
    print_status "📋 Current Status:"
    echo ""
    echo "=== Docker Compose Services ==="
    docker-compose ps
    echo ""
    echo "=== Container Resource Usage ==="
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" 2>/dev/null || echo "No running containers"
}

# Function to show help
show_help() {
    echo "YuBlog Quick Development Script"
    echo ""
    echo "Usage: ./dev.sh [command]"
    echo ""
    echo "Commands:"
    echo "  restart, r    - Quick restart with code refresh (DEFAULT - most common)"
    echo "  rebuild, rb   - Full rebuild with cache clearing"
    echo "  logs, l       - Show backend logs in real-time"
    echo "  status, s     - Show service status"
    echo "  help, h       - Show this help"
    echo ""
    echo "Examples:"
    echo "  ./dev.sh              # Quick restart (default)"
    echo "  ./dev.sh restart      # Same as above"
    echo "  ./dev.sh rebuild      # Full rebuild"
    echo "  ./dev.sh logs         # Watch logs"
    echo ""
    echo "💡 For most code changes, just run: ./dev.sh"
}

# Main script logic
main() {
    check_docker
    
    local command=${1:-restart}
    
    case $command in
        restart|r|"")
            restart_fresh
            ;;
        rebuild|rb)
            full_rebuild
            ;;
        logs|l)
            show_logs
            ;;
        status|s)
            show_status
            ;;
        help|h|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@" 