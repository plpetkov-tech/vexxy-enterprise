## ZAP Connectivity Fix - Quick Guide

The issue: Port-forward keeps dying or `host.docker.internal` doesn't work properly from Docker containers.

### Solution 1: Use Host Network Mode (Easiest)

Update `docker-compose.yml` for api and worker services:

```yaml
services:
  api:
    network_mode: "host"  # Add this line
    # Remove ports: section since host mode doesn't need it
    environment:
      ZAP_HOST: localhost  # Change from host.docker.internal
```

Then:
```bash
# Restart services
docker-compose down
kubectl port-forward -n security svc/owasp-zap 8080:8080 &
docker-compose up -d
```

### Solution 2: Use Docker Bridge IP

Find the Docker bridge gateway IP:
```bash
docker network inspect bridge | grep Gateway
# Usually: 172.17.0.1
```

Update docker-compose.yml:
```yaml
services:
  api:
    environment:
      ZAP_HOST: 172.17.0.1  # Use the bridge IP
```

Then:
```bash
# Restart
docker-compose restart api worker
```

### Solution 3: Run ZAP in Docker (No Kubernetes needed for dev)

```bash
# Stop current setup
docker-compose down

# Run ZAP in Docker
docker run -d --name zap \
  -p 8080:8080 \
  -e "ZAP_JAVA_OPTS=-Xmx512m" \
  zaproxy/zap-stable zap.sh -daemon \
  -host 0.0.0.0 -port 8080 \
  -config api.disablekey=true

# Update docker-compose.yml
# Change ZAP_HOST to: host.docker.internal (or bridge IP)

# Start services
docker-compose up -d
```

### Test Connectivity

From inside the API container:
```bash
# Get into container
docker exec -it vexxy-premium-api bash

# Test ZAP connection
curl http://host.docker.internal:8080/JSON/core/view/version/
# OR
curl http://172.17.0.1:8080/JSON/core/view/version/
# OR
curl http://localhost:8080/JSON/core/view/version/  # if using host network

# If it works, you'll see: {"version":"2.14.0"}
```

### Verify Which Solution Worked

```bash
# Check logs
docker-compose logs api | grep -i zap

# Should see:
# INFO - ZAP is available, version: 2.14.0
```

### Keep Port-Forward Alive (If using Kubernetes ZAP)

Run in a separate terminal and keep it running:
```bash
cd premium-service
./scripts/keep-zap-alive.sh
```

Or use screen/tmux:
```bash
screen -S zap-forward
./scripts/keep-zap-alive.sh
# Press Ctrl+A, D to detach
# screen -r zap-forward to reattach
```
