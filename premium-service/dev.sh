#!/bin/bash
# VEXxy Premium Service Development Helper
# Manages Docker Compose, Kubernetes port-forwarding, and service health checks

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.yml"
ZAP_NAMESPACE="security"
ZAP_SERVICE="owasp-zap"
ZAP_PORT="8080"
PORT_FORWARD_PID_FILE="/tmp/vexxy-zap-port-forward.pid"

# Print colored output
print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."

    local missing=0

    if ! command -v docker &> /dev/null; then
        print_error "docker is not installed"
        missing=1
    fi

    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "docker-compose is not installed"
        missing=1
    fi

    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl is not installed"
        missing=1
    fi

    if [ $missing -eq 1 ]; then
        exit 1
    fi

    print_success "All prerequisites met"
}

# Check if ZAP is running in Kubernetes
check_zap_deployment() {
    print_info "Checking OWASP ZAP deployment..."

    if ! kubectl get deployment -n "$ZAP_NAMESPACE" "$ZAP_SERVICE" &> /dev/null; then
        print_warning "OWASP ZAP deployment not found in namespace '$ZAP_NAMESPACE'"
        print_info "Security scanning will be skipped"
        return 1
    fi

    if ! kubectl get pods -n "$ZAP_NAMESPACE" -l "app.kubernetes.io/name=owasp-zap" --field-selector=status.phase=Running &> /dev/null; then
        print_warning "OWASP ZAP pod is not running"
        return 1
    fi

    print_success "OWASP ZAP is deployed and running"
    return 0
}

# Start port-forward to ZAP
start_port_forward() {
    print_info "Starting port-forward to OWASP ZAP..."

    # Check if port-forward is already running
    if [ -f "$PORT_FORWARD_PID_FILE" ]; then
        local old_pid=$(cat "$PORT_FORWARD_PID_FILE")
        if kill -0 "$old_pid" 2>/dev/null; then
            print_warning "Port-forward already running (PID: $old_pid)"
            return 0
        else
            rm -f "$PORT_FORWARD_PID_FILE"
        fi
    fi

    # Start port-forward in background
    kubectl port-forward -n "$ZAP_NAMESPACE" "svc/$ZAP_SERVICE" "$ZAP_PORT:$ZAP_PORT" > /tmp/zap-port-forward.log 2>&1 &
    local pid=$!
    echo "$pid" > "$PORT_FORWARD_PID_FILE"

    # Wait for port-forward to be ready
    sleep 2

    if ! kill -0 "$pid" 2>/dev/null; then
        print_error "Port-forward failed to start"
        cat /tmp/zap-port-forward.log
        rm -f "$PORT_FORWARD_PID_FILE"
        return 1
    fi

    # Test connection
    if curl -s "http://localhost:$ZAP_PORT/JSON/core/view/version/" > /dev/null 2>&1; then
        print_success "Port-forward established (PID: $pid)"
    else
        print_warning "Port-forward started but ZAP not responding yet (might need more time)"
    fi
}

# Stop port-forward
stop_port_forward() {
    if [ -f "$PORT_FORWARD_PID_FILE" ]; then
        local pid=$(cat "$PORT_FORWARD_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            print_info "Stopping port-forward (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            rm -f "$PORT_FORWARD_PID_FILE"
            print_success "Port-forward stopped"
        else
            rm -f "$PORT_FORWARD_PID_FILE"
        fi
    fi
}

# Run database migrations
run_migrations() {
    print_info "Running database migrations..."

    # Wait for postgres to be ready
    local retries=0
    while [ $retries -lt 30 ]; do
        if docker-compose exec -T postgres pg_isready -U vexxy -d vexxy_premium > /dev/null 2>&1; then
            break
        fi
        retries=$((retries + 1))
        sleep 1
    done

    # Run migrations
    if [ -d "migrations" ] && [ "$(ls -A migrations/*.sql 2>/dev/null)" ]; then
        for migration in migrations/*.sql; do
            print_info "Running migration: $(basename $migration)"
            docker-compose exec -T postgres psql -U vexxy -d vexxy_premium < "$migration" 2>/dev/null || {
                print_warning "Migration $(basename $migration) already applied or failed (this might be OK)"
            }
        done
        print_success "Migrations completed"
    else
        print_info "No migrations to run"
    fi
}

# Wait for services to be healthy
wait_for_services() {
    print_info "Waiting for services to be healthy..."

    local services=("postgres" "redis" "api" "worker")
    local timeout=120
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        local all_healthy=true

        for service in "${services[@]}"; do
            local health=$(docker-compose ps -q "$service" 2>/dev/null | xargs -r docker inspect --format='{{.State.Health.Status}}' 2>/dev/null || echo "unknown")

            if [ "$health" != "healthy" ] && [ "$health" != "unknown" ]; then
                all_healthy=false
                break
            fi
        done

        if $all_healthy; then
            print_success "All services are healthy"
            return 0
        fi

        sleep 2
        elapsed=$((elapsed + 2))

        # Show progress
        if [ $((elapsed % 10)) -eq 0 ]; then
            print_info "Still waiting... ($elapsed/$timeout seconds)"
        fi
    done

    print_warning "Services did not become healthy within timeout"
    print_info "You can check status with: docker-compose ps"
    return 1
}

# Show service status
show_status() {
    print_header "Service Status"

    echo "Docker Compose Services:"
    docker-compose ps

    echo ""
    echo "Health Checks:"
    for service in postgres redis api worker; do
        local health=$(docker-compose ps -q "$service" 2>/dev/null | xargs -r docker inspect --format='{{.State.Health.Status}}' 2>/dev/null || echo "not running")
        if [ "$health" = "healthy" ]; then
            echo -e "  ${GREEN}✓${NC} $service: $health"
        elif [ "$health" = "not running" ]; then
            echo -e "  ${RED}✗${NC} $service: $health"
        else
            echo -e "  ${YELLOW}⚠${NC} $service: $health"
        fi
    done

    echo ""
    echo "Port Forward:"
    if [ -f "$PORT_FORWARD_PID_FILE" ]; then
        local pid=$(cat "$PORT_FORWARD_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} OWASP ZAP port-forward running (PID: $pid)"
        else
            echo -e "  ${RED}✗${NC} OWASP ZAP port-forward not running (stale PID file)"
        fi
    else
        echo -e "  ${YELLOW}⚠${NC} OWASP ZAP port-forward not running"
    fi

    echo ""
    echo "Endpoints:"
    echo "  API:    http://localhost:8001"
    echo "  Flower: http://localhost:5555"
    echo "  Docs:   http://localhost:8001/docs"
}

# Show logs
show_logs() {
    local service=$1
    if [ -z "$service" ]; then
        docker-compose logs -f
    else
        docker-compose logs -f "$service"
    fi
}

# Clean up everything
cleanup() {
    print_header "Cleaning Up"

    print_info "Stopping Docker Compose services..."
    docker-compose down -v

    stop_port_forward

    print_success "Cleanup completed"
}

# Start everything
start() {
    print_header "Starting VEXxy Premium Service"

    check_prerequisites

    # Check ZAP and start port-forward if available
    if check_zap_deployment; then
        start_port_forward || print_warning "Failed to start port-forward, continuing anyway"
    fi

    print_info "Building and starting Docker Compose services..."
    docker-compose up --build -d

    run_migrations

    wait_for_services

    print_header "Services Started Successfully!"
    show_status

    echo ""
    print_info "Next steps:"
    echo "  • View logs:      ./dev.sh logs [service]"
    echo "  • Check status:   ./dev.sh status"
    echo "  • Run tests:      ./dev.sh test"
    echo "  • Stop services:  ./dev.sh stop"
    echo ""
}

# Stop everything
stop() {
    print_header "Stopping VEXxy Premium Service"

    print_info "Stopping Docker Compose services..."
    docker-compose down

    stop_port_forward

    print_success "Services stopped"
}

# Restart everything
restart() {
    print_header "Restarting VEXxy Premium Service"

    stop
    sleep 2
    start
}

# Run a quick test
test() {
    print_header "Running Quick Test"

    print_info "Testing API health endpoint..."
    if curl -f http://localhost:8001/health > /dev/null 2>&1; then
        print_success "API is responding"
    else
        print_error "API health check failed"
        return 1
    fi

    print_info "Testing ZAP connection..."
    if curl -f http://localhost:8080/JSON/core/view/version/ > /dev/null 2>&1; then
        print_success "OWASP ZAP is accessible"
    else
        print_warning "OWASP ZAP is not accessible (security scans will be skipped)"
    fi

    print_success "Tests passed"
}

# Interactive mode - run and follow logs
run() {
    # Set up cleanup trap
    trap 'echo ""; print_info "Shutting down..."; cleanup; exit 0' INT TERM

    start

    print_info "Following logs (Ctrl+C to stop)..."
    docker-compose logs -f
}

# Show help
show_help() {
    cat << EOF
VEXxy Premium Service Development Helper

Usage: $0 <command>

Commands:
    start       Build and start all services in background
    stop        Stop all services (keeps data)
    restart     Restart all services
    down        Stop and remove all services and volumes
    run         Start services and follow logs (Ctrl+C to stop)

    status      Show service status
    logs        Show logs (optionally specify service name)
    test        Run quick health check tests

    shell       Open shell in service container
    psql        Connect to PostgreSQL database
    redis-cli   Connect to Redis

Examples:
    $0 run                    # Start and follow logs
    $0 start                  # Start in background
    $0 logs worker            # Show worker logs
    $0 shell api              # Open shell in API container
    $0 test                   # Run health checks

Environment Variables:
    ZAP_HOST                  # OWASP ZAP host (default: host.docker.internal)
    ZAP_PORT                  # OWASP ZAP port (default: 8080)

EOF
}

# Open shell in container
open_shell() {
    local service=${1:-api}
    print_info "Opening shell in $service container..."
    docker-compose exec "$service" /bin/bash
}

# Connect to PostgreSQL
connect_psql() {
    print_info "Connecting to PostgreSQL..."
    docker-compose exec postgres psql -U vexxy -d vexxy_premium
}

# Connect to Redis
connect_redis() {
    print_info "Connecting to Redis..."
    docker-compose exec redis redis-cli
}

# Main command dispatcher
main() {
    local command=${1:-help}

    case $command in
        start)
            start
            ;;
        stop)
            stop
            ;;
        down)
            cleanup
            ;;
        restart)
            restart
            ;;
        run)
            run
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs "${2}"
            ;;
        test)
            test
            ;;
        shell)
            open_shell "${2}"
            ;;
        psql)
            connect_psql
            ;;
        redis-cli)
            connect_redis
            ;;
        help|--help|-h)
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

# Change to script directory
cd "$(dirname "$0")"

# Run main
main "$@"
