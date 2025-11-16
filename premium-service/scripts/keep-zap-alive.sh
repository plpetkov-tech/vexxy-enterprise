#!/bin/bash
# Keep ZAP port-forward alive
# This script monitors and restarts the port-forward if it dies

ZAP_NAMESPACE="security"
ZAP_SERVICE="owasp-zap"
ZAP_PORT="8080"
PID_FILE="/tmp/vexxy-zap-port-forward.pid"
LOG_FILE="/tmp/zap-port-forward.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Starting ZAP port-forward monitor..."

cleanup() {
    echo -e "\n${YELLOW}Stopping port-forward...${NC}"
    if [ -f "$PID_FILE" ]; then
        kill $(cat "$PID_FILE") 2>/dev/null
        rm -f "$PID_FILE"
    fi
    exit 0
}

trap cleanup INT TERM

start_port_forward() {
    # Kill existing port-forward
    if [ -f "$PID_FILE" ]; then
        kill $(cat "$PID_FILE") 2>/dev/null
        rm -f "$PID_FILE"
    fi

    # Start new port-forward
    kubectl port-forward -n "$ZAP_NAMESPACE" "svc/$ZAP_SERVICE" "$ZAP_PORT:$ZAP_PORT" > "$LOG_FILE" 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_FILE"

    # Wait a moment for it to start
    sleep 2

    # Check if it's running
    if kill -0 "$pid" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Port-forward started (PID: $pid)"
        return 0
    else
        echo -e "${RED}✗${NC} Port-forward failed to start"
        cat "$LOG_FILE"
        return 1
    fi
}

check_port_forward() {
    if [ ! -f "$PID_FILE" ]; then
        return 1
    fi

    local pid=$(cat "$PID_FILE")
    if ! kill -0 "$pid" 2>/dev/null; then
        return 1
    fi

    # Test actual connectivity
    if ! curl -s -f "http://localhost:$ZAP_PORT/JSON/core/view/version/" > /dev/null 2>&1; then
        return 1
    fi

    return 0
}

# Start initial port-forward
start_port_forward || exit 1

echo "Monitoring port-forward (Ctrl+C to stop)..."

# Monitor loop
while true; do
    sleep 5

    if ! check_port_forward; then
        echo -e "${YELLOW}⚠${NC} Port-forward died, restarting..."
        start_port_forward
    fi
done
