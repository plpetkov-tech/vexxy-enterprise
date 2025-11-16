# OWASP ZAP Setup for Docker Development

This document explains how to connect the premium-service Docker containers to OWASP ZAP running in Kubernetes.

## The Problem

The premium-service API and worker containers run in Docker (outside Kubernetes), but OWASP ZAP runs inside the Kubernetes cluster. Docker containers cannot directly access Kubernetes service DNS names like `owasp-zap.security.svc.cluster.local`.

## Solution: Port Forwarding

Use `kubectl port-forward` to expose the ZAP service to your host machine, which Docker can then access via `host.docker.internal`.

### Step 1: Start Port Forward

In a separate terminal, run:

```bash
kubectl port-forward -n security svc/owasp-zap 8080:8080
```

Keep this running while you're developing. You should see:

```
Forwarding from 127.0.0.1:8080 -> 8080
Forwarding from [::1]:8080 -> 8080
```

### Step 2: Verify ZAP is Accessible

Test the connection:

```bash
curl http://localhost:8080/JSON/core/view/version/
```

You should see a JSON response with ZAP version info.

### Step 3: Start Docker Services

The docker-compose configuration is already set up to use `host.docker.internal:8080` by default:

```bash
cd premium-service
docker-compose up
```

The services will automatically connect to ZAP through the port-forward.

## Alternative Solutions

### Option 1: NodePort Service

Expose ZAP via NodePort (not recommended for production):

```bash
kubectl patch svc owasp-zap -n security -p '{"spec":{"type":"NodePort"}}'
```

Then find the assigned port:

```bash
kubectl get svc owasp-zap -n security
```

Update docker-compose environment:

```yaml
environment:
  ZAP_HOST: <node-ip>
  ZAP_PORT: <nodeport>
```

### Option 2: In-Cluster Deployment

Deploy the premium-service inside Kubernetes instead of Docker:

1. Build container image
2. Deploy to Kubernetes
3. Set `K8S_IN_CLUSTER=true`
4. Use Kubernetes DNS: `ZAP_HOST=owasp-zap.security.svc.cluster.local`

## Configuration

### Environment Variables

You can configure ZAP connection via environment variables or `.env` file:

```bash
# .env
ZAP_HOST=localhost
ZAP_PORT=8080
ZAP_API_KEY=vexxy-zap-key
ZAP_NAMESPACE=security
```

### Docker Compose Override

For custom configurations, create `docker-compose.override.yml`:

```yaml
version: '3.8'

services:
  api:
    environment:
      ZAP_HOST: custom-zap-host
      ZAP_PORT: 9090

  worker:
    environment:
      ZAP_HOST: custom-zap-host
      ZAP_PORT: 9090
```

## Troubleshooting

### "ZAP is not available" Error

**Symptom:**
```
WARNING - ZAP is not available: HTTPConnectionPool...Failed to establish a new connection
```

**Solutions:**

1. **Check port-forward is running:**
   ```bash
   # Should show kubectl port-forward process
   ps aux | grep "port-forward.*zap"
   ```

2. **Verify ZAP pod is running:**
   ```bash
   kubectl get pods -n security | grep zap
   ```

3. **Test ZAP directly:**
   ```bash
   curl http://localhost:8080/JSON/core/view/version/
   ```

4. **Check Docker network:**
   ```bash
   # From inside container
   docker exec vexxy-premium-api curl http://host.docker.internal:8080/JSON/core/view/version/
   ```

### Connection Refused

If you get "Connection refused", ZAP might not be ready yet. Wait 30-60 seconds for ZAP to start.

### DNS Resolution Failed

If you see "Name or service not known", the container can't resolve `host.docker.internal`. Make sure:

1. Docker version is recent (20.10+)
2. `extra_hosts` is configured in docker-compose
3. On Linux, `host.docker.internal` maps to `172.17.0.1` (Docker bridge gateway)

## Development Workflow

### Recommended Setup

1. Start port-forward in terminal 1:
   ```bash
   kubectl port-forward -n security svc/owasp-zap 8080:8080
   ```

2. Start services in terminal 2:
   ```bash
   cd premium-service
   docker-compose up
   ```

3. Monitor logs in terminal 3:
   ```bash
   docker-compose logs -f api worker
   ```

### Quick Test

Run a quick analysis to verify ZAP integration:

```bash
curl -X POST http://localhost:8001/api/v1/analysis \
  -H "Content-Type: application/json" \
  -d '{
    "image_ref": "nginx:latest",
    "image_digest": "sha256:...",
    "config": {
      "ports": [80],
      "enable_fuzzing": true,
      "analysis_duration": 60
    }
  }'
```

Check logs for ZAP scan activity:

```bash
docker-compose logs -f worker | grep -i zap
```

## Production Deployment

For production:

1. Deploy premium-service **inside** Kubernetes
2. Use Kubernetes service DNS directly
3. No port-forwarding needed
4. Set `K8S_IN_CLUSTER=true`

See `k8s/` directory for deployment manifests.
