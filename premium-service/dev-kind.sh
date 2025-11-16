#!/bin/bash
# VEXxy Premium Service - Kind-based Development Environment
# Everything runs in Kubernetes - no Docker Compose!

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CLUSTER_NAME="vexxy"
IMAGE_NAME="vexxy-premium"
IMAGE_TAG="latest"
NAMESPACE="vexxy-premium"

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

check_prerequisites() {
    print_info "Checking prerequisites..."
    local missing=0

    if ! command -v docker &> /dev/null; then
        print_error "docker is not installed"
        missing=1
    fi

    if ! command -v kind &> /dev/null; then
        print_error "kind is not installed (https://kind.sigs.k8s.io/)"
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

check_cluster() {
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        return 0
    fi
    return 1
}

create_cluster() {
    print_header "Creating Kind Cluster"

    if check_cluster; then
        print_warning "Cluster '$CLUSTER_NAME' already exists"
        return 0
    fi

    print_info "Creating kind cluster '$CLUSTER_NAME'..."

    # Create cluster with port mappings for services
    cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30001  # API
    hostPort: 8001
    protocol: TCP
  - containerPort: 30555  # Flower
    hostPort: 5555
    protocol: TCP
EOF

    print_success "Cluster created"
}

install_infrastructure() {
    print_header "Installing Infrastructure (Kubescape + OWASP ZAP)"

    # Install Kubescape via Helm (idempotent)
    print_info "Installing Kubescape..."

    # Check if Helm is installed
    if ! command -v helm &> /dev/null; then
        print_error "Helm is not installed (https://helm.sh/docs/intro/install/)"
        return 1
    fi

    # Add Kubescape Helm repo (force update if exists)
    helm repo add kubescape https://kubescape.github.io/helm-charts --force-update 2>/dev/null || true
    helm repo update 2>/dev/null || true

    # Check if Kubescape is already installed
    if helm list -n kubescape 2>/dev/null | grep -q kubescape; then
        print_info "Kubescape is already installed, skipping..."
    else
        print_info "Installing Kubescape operator (this may take a few minutes)..."

        # Create Helm values for Kubescape
        cat > /tmp/kubescape-values.yaml <<EOF
capabilities:
  vexGeneration: enable
  vulnerabilityScan: enable
  relevancy: enable
  runtimeObservability: enable
  networkEventsStreaming: disable

nodeAgent:
  enabled: true
  config:
    applicationActivityTime: 5m
    learningPeriod: 5m
    maxLearningPeriod: 5m
    updatePeriod: 1m

kubevuln:
  enabled: true
  config:
    storeFilteredSbom: true

storage:
  enabled: true

grypeOfflineDB:
  enabled: true
EOF

        # Install Kubescape (idempotent with upgrade --install)
        helm upgrade --install kubescape kubescape/kubescape-operator \
            -n kubescape \
            --create-namespace \
            -f /tmp/kubescape-values.yaml \
            --wait \
            --timeout 5m

        rm -f /tmp/kubescape-values.yaml
        print_success "Kubescape installed"
    fi

    # Install OWASP ZAP (idempotent)
    print_info "Installing OWASP ZAP..."

    # Create security namespace if it doesn't exist
    kubectl create namespace security 2>/dev/null || true

    # Check if ZAP is already deployed
    if kubectl get deployment owasp-zap -n security &>/dev/null; then
        print_info "OWASP ZAP is already installed, skipping..."
    else
        print_info "Deploying OWASP ZAP..."

        # Create ZAP deployment and service
        cat <<EOF | kubectl apply -f -
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: owasp-zap
  namespace: security
  labels:
    app: owasp-zap
    vexxy.dev/component: security
spec:
  replicas: 1
  selector:
    matchLabels:
      app: owasp-zap
  template:
    metadata:
      labels:
        app: owasp-zap
    spec:
      containers:
      - name: zap
        image: ghcr.io/zaproxy/zaproxy:stable
        command: ["zap.sh"]
        args:
          - "-daemon"
          - "-host"
          - "0.0.0.0"
          - "-port"
          - "8080"
          - "-config"
          - "api.disablekey=true"
          - "-config"
          - "api.addrs.addr.name=.*"
          - "-config"
          - "api.addrs.addr.regex=true"
        ports:
        - containerPort: 8080
          protocol: TCP
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 2
            memory: 2Gi
        livenessProbe:
          httpGet:
            path: /
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: owasp-zap
  namespace: security
  labels:
    app: owasp-zap
    vexxy.dev/component: security
spec:
  type: ClusterIP
  selector:
    app: owasp-zap
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
    name: http
EOF

        print_info "Waiting for ZAP to be ready..."
        kubectl wait --for=condition=ready pod -l app=owasp-zap -n security --timeout=120s || true
        print_success "OWASP ZAP installed"
    fi

    print_success "Infrastructure installation complete"
}

build_image() {
    print_header "Building Docker Image"

    print_info "Building image $IMAGE_NAME:$IMAGE_TAG..."
    docker build -t "$IMAGE_NAME:$IMAGE_TAG" .

    print_info "Loading image into kind cluster..."
    kind load docker-image "$IMAGE_NAME:$IMAGE_TAG" --name "$CLUSTER_NAME"

    print_success "Image built and loaded"
}

deploy_services() {
    print_header "Deploying Services"

    print_info "Applying Kubernetes manifests..."
    kubectl apply -k k8s/

    print_info "Waiting for database to be ready..."
    kubectl wait --for=condition=ready pod -l app=postgres -n "$NAMESPACE" --timeout=120s || true

    print_info "Running database migrations..."
    # Get postgres pod name
    local postgres_pod=$(kubectl get pods -n "$NAMESPACE" -l app=postgres -o jsonpath='{.items[0].metadata.name}')
    if [ -n "$postgres_pod" ]; then
        if [ -d "migrations" ]; then
            for migration in migrations/*.sql; do
                if [ -f "$migration" ]; then
                    print_info "Running migration: $(basename $migration)"
                    kubectl exec -n "$NAMESPACE" "$postgres_pod" -- psql -U vexxy -d vexxy_premium < "$migration" 2>/dev/null || true
                fi
            done
        fi
    fi

    print_info "Waiting for services to be ready..."
    kubectl wait --for=condition=ready pod -l app=premium-api -n "$NAMESPACE" --timeout=120s || true
    kubectl wait --for=condition=ready pod -l app=premium-worker -n "$NAMESPACE" --timeout=120s || true

    print_success "Services deployed"
}

show_status() {
    print_header "Service Status"

    echo "Pods:"
    kubectl get pods -n "$NAMESPACE"

    echo ""
    echo "Services:"
    kubectl get svc -n "$NAMESPACE"

    echo ""
    echo "Endpoints:"
    echo "  API:    http://localhost:8001"
    echo "  Docs:   http://localhost:8001/docs"
    echo "  Flower: http://localhost:5555"

    echo ""
    print_info "To access API from outside kind:"
    echo "  curl http://localhost:8001/health"
}

show_logs() {
    local service=${1:-""}

    if [ -z "$service" ]; then
        print_info "Available services: api, worker, postgres, redis, flower"
        echo "Usage: $0 logs <service>"
        return 1
    fi

    case $service in
        api)
            kubectl logs -n "$NAMESPACE" -l app=premium-api -f --all-containers
            ;;
        worker)
            kubectl logs -n "$NAMESPACE" -l app=premium-worker -f --all-containers
            ;;
        flower)
            kubectl logs -n "$NAMESPACE" -l app=premium-flower -f --all-containers
            ;;
        postgres)
            kubectl logs -n "$NAMESPACE" -l app=postgres -f
            ;;
        redis)
            kubectl logs -n "$NAMESPACE" -l app=redis -f
            ;;
        *)
            print_error "Unknown service: $service"
            return 1
            ;;
    esac
}

cleanup() {
    print_header "Cleaning Up"

    print_info "Deleting namespace..."
    kubectl delete namespace "$NAMESPACE" --wait=false 2>/dev/null || true

    print_success "Cleanup initiated"
}

destroy() {
    print_header "Destroying Cluster"

    if ! check_cluster; then
        print_warning "Cluster '$CLUSTER_NAME' does not exist"
        return 0
    fi

    print_info "Deleting kind cluster '$CLUSTER_NAME'..."
    kind delete cluster --name "$CLUSTER_NAME"

    print_success "Cluster destroyed"
}

start() {
    print_header "Starting VEXxy Premium Service (Kind)"

    check_prerequisites

    if ! check_cluster; then
        create_cluster
    fi

    install_infrastructure
    build_image
    deploy_services
    show_status

    print_header "Ready!"
    echo ""
    print_info "Next steps:"
    echo "  • View logs:    $0 logs api"
    echo "  • Test API:     curl http://localhost:8001/health"
    echo "  • Stop:         $0 stop"
    echo "  • Destroy:      $0 destroy"
    echo ""
}

restart() {
    print_header "Restarting Services"

    build_image
    kubectl rollout restart deployment -n "$NAMESPACE"

    print_info "Waiting for rollout..."
    kubectl rollout status deployment/premium-api -n "$NAMESPACE"
    kubectl rollout status deployment/premium-worker -n "$NAMESPACE"

    print_success "Services restarted"
}

update() {
    print_header "Updating Manifests"

    print_info "Applying Kubernetes manifests..."
    kubectl apply -k k8s/

    print_info "Restarting deployments to pick up changes..."
    kubectl rollout restart deployment -n "$NAMESPACE"

    print_success "Manifests updated"
}

debug() {
    print_header "Debug Information"

    echo "=== API Pod Status ==="
    kubectl get pods -n "$NAMESPACE" -l app=premium-api

    echo ""
    echo "=== Recent API Logs ==="
    kubectl logs -n "$NAMESPACE" -l app=premium-api --tail=50 --all-containers || true

    echo ""
    echo "=== API Pod Events ==="
    kubectl get events -n "$NAMESPACE" --field-selector involvedObject.kind=Pod --sort-by='.lastTimestamp' | grep premium-api | tail -10

    echo ""
    echo "=== ServiceAccount Permissions ==="
    kubectl auth can-i --list --as=system:serviceaccount:vexxy-premium:premium-service -n kubescape | head -20
}

test() {
    print_header "Running Tests"

    print_info "Testing API health..."
    if curl -f http://localhost:8001/health > /dev/null 2>&1; then
        print_success "API is responding"
    else
        print_error "API health check failed"
        return 1
    fi

    print_info "Testing ZAP connectivity (from inside cluster)..."
    local api_pod=$(kubectl get pods -n "$NAMESPACE" -l app=premium-api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [ -n "$api_pod" ]; then
        if kubectl exec -n "$NAMESPACE" "$api_pod" -- curl -sf http://owasp-zap.security.svc.cluster.local:8080/JSON/core/view/version/ > /dev/null 2>&1; then
            print_success "ZAP is accessible from pods"
        else
            print_warning "ZAP is not accessible (this is OK if not installed)"
        fi
    fi

    print_success "Tests passed"
}

shell() {
    local service=${1:-api}

    local label=""
    case $service in
        api) label="app=premium-api" ;;
        worker) label="app=premium-worker" ;;
        postgres) label="app=postgres" ;;
        redis) label="app=redis" ;;
        *) print_error "Unknown service: $service"; return 1 ;;
    esac

    local pod=$(kubectl get pods -n "$NAMESPACE" -l "$label" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [ -z "$pod" ]; then
        print_error "No pod found for service: $service"
        return 1
    fi

    print_info "Opening shell in $pod..."
    kubectl exec -it -n "$NAMESPACE" "$pod" -- /bin/bash
}

psql() {
    local postgres_pod=$(kubectl get pods -n "$NAMESPACE" -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [ -z "$postgres_pod" ]; then
        print_error "PostgreSQL pod not found"
        return 1
    fi

    print_info "Connecting to PostgreSQL..."
    kubectl exec -it -n "$NAMESPACE" "$postgres_pod" -- psql -U vexxy -d vexxy_premium
}

show_help() {
    cat << EOF
VEXxy Premium Service - Kind Development Environment

Everything runs in Kubernetes - no Docker Compose needed!

Usage: $0 <command>

Commands:
    start       Create cluster and deploy all services
    stop        Delete services (keeps cluster)
    restart     Rebuild image and restart services
    update      Apply manifest changes without rebuilding
    destroy     Delete entire kind cluster

    status      Show pod and service status
    logs        Show logs (specify: api, worker, postgres, redis, flower)
    debug       Show debug info (pod status, logs, events, RBAC)
    test        Run health checks

    shell       Open shell in pod (specify: api, worker, postgres, redis)
    psql        Connect to PostgreSQL database

Examples:
    $0 start                 # Deploy everything
    $0 update                # Apply RBAC/config changes
    $0 debug                 # Debug API issues
    $0 logs api              # View API logs
    $0 shell worker          # Shell in worker pod
    $0 test                  # Run health checks
    $0 destroy               # Clean up everything

Benefits of Kind:
  ✓ Everything in Kubernetes (like production)
  ✓ No networking issues - K8s service DNS works perfectly
  ✓ No port-forwarding needed
  ✓ Clean isolation
  ✓ Easy to reset (kind delete cluster)

EOF
}

# Main
main() {
    local command=${1:-help}

    case $command in
        start) start ;;
        stop) cleanup ;;
        restart) restart ;;
        update) update ;;
        destroy) destroy ;;
        status) show_status ;;
        logs) show_logs "${2}" ;;
        debug) debug ;;
        test) test ;;
        shell) shell "${2}" ;;
        psql) psql ;;
        help|--help|-h) show_help ;;
        *)
            print_error "Unknown command: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

cd "$(dirname "$0")"
main "$@"
