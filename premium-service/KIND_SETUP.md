# Kind-Based Development Setup

**New and Improved!** Everything runs in Kubernetes using kind - no more Docker Compose networking issues!

## Why Kind?

The premium service launches analysis jobs in Kubernetes anyway, so running the entire stack in the same kind cluster makes way more sense:

✅ **No networking issues** - Everything uses Kubernetes service DNS
✅ **Production-like** - Same environment as production
✅ **No port-forwarding** - Services communicate directly
✅ **Simpler** - One tool (kubectl) instead of mixing docker-compose + kubectl
✅ **Clean isolation** - Easy to reset with `kind delete cluster`

## Quick Start

### Prerequisites

Install kind if you don't have it:
```bash
# On macOS
brew install kind

# On Linux
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

### One-Command Setup

```bash
cd premium-service

# Deploy everything to kind
./dev-kind.sh start
```

This will:
1. Create a kind cluster named 'vexxy'
2. Build the Docker image
3. Load it into kind
4. Deploy PostgreSQL, Redis, API, Worker
5. Run database migrations
6. Expose services via NodePorts

### Access Services

```bash
# API
curl http://localhost:8001/health

# API Docs
open http://localhost:8001/docs

# Flower (Celery monitoring)
open http://localhost:5555
```

## Commands

```bash
./dev-kind.sh start      # Deploy everything
./dev-kind.sh stop       # Delete services (keeps cluster)
./dev-kind.sh restart    # Rebuild image and restart
./dev-kind.sh destroy    # Delete entire cluster

./dev-kind.sh status     # Show pods and services
./dev-kind.sh logs api   # View logs
./dev-kind.sh test       # Run health checks

./dev-kind.sh shell api  # Shell into pod
./dev-kind.sh psql       # PostgreSQL client
```

## How It Works

### Architecture

```
kind cluster "vexxy"
├── namespace: vexxy-premium
│   ├── PostgreSQL (StatefulSet)
│   ├── Redis (Deployment)
│   ├── API (Deployment) - NodePort 30001 → localhost:8001
│   ├── Worker (Deployment)
│   └── Flower (Deployment) - NodePort 30555 → localhost:5555
│
├── namespace: vexxy-sandbox
│   └── Analysis jobs run here
│
├── namespace: security
│   └── OWASP ZAP (already deployed)
│
└── namespace: kubescape
    └── Kubescape (already deployed)
```

### Service Communication

All services use Kubernetes DNS - no networking hacks needed:

```yaml
# API/Worker → PostgreSQL
DATABASE_URL: postgresql://vexxy:vexxy@postgres.vexxy-premium.svc.cluster.local:5432/vexxy_premium

# API/Worker → Redis
REDIS_URL: redis://redis.vexxy-premium.svc.cluster.local:6379/0

# API/Worker → OWASP ZAP
ZAP_HOST: owasp-zap.security.svc.cluster.local
ZAP_PORT: 8080

# Worker → Analysis Pods
# Deployed to vexxy-sandbox namespace
```

### Port Mapping

kind maps container ports to localhost:

```bash
API:    30001 (in cluster) → 8001 (localhost)
Flower: 30555 (in cluster) → 5555 (localhost)
```

## Development Workflow

### Making Code Changes

```bash
# Edit code
vim api/main.py

# Rebuild and redeploy
./dev-kind.sh restart

# Watch logs
./dev-kind.sh logs api
```

### Database Migrations

```bash
# Migrations run automatically on ./dev-kind.sh start

# Or run manually
./dev-kind.sh psql < migrations/new_migration.sql
```

### Debugging

```bash
# Get a shell in API pod
./dev-kind.sh shell api

# Inside pod, test connectivity
curl http://postgres.vexxy-premium.svc.cluster.local:5432
curl http://owasp-zap.security.svc.cluster.local:8080/JSON/core/view/version/

# View all pods
kubectl get pods -n vexxy-premium

# Describe a pod
kubectl describe pod -n vexxy-premium premium-api-xxxxx

# View events
kubectl get events -n vexxy-premium --sort-by='.lastTimestamp'
```

### Testing

```bash
# Run health checks
./dev-kind.sh test

# Submit analysis job
curl -X POST http://localhost:8001/api/v1/analysis \
  -H "Content-Type: application/json" \
  -d '{
    "image_ref": "nginx:latest",
    "image_digest": "sha256:abc123...",
    "config": {
      "ports": [80],
      "enable_fuzzing": true
    }
  }'

# Check status
JOB_ID="..."
curl http://localhost:8001/api/v1/analysis/$JOB_ID/status

# View worker logs
./dev-kind.sh logs worker
```

## Comparison: Docker Compose vs Kind

### Docker Compose (Old)
```bash
# Problems:
❌ API/Worker in Docker, analysis jobs in K8s (split)
❌ Complex networking (host.docker.internal, bridge IPs)
❌ Port-forwarding required for ZAP
❌ Port-forward keeps dying
❌ Not like production

# Start
docker-compose up
kubectl port-forward -n security svc/owasp-zap 8080:8080 &
```

### Kind (New)
```bash
# Benefits:
✅ Everything in Kubernetes
✅ Service DNS just works
✅ No port-forwarding needed
✅ Like production

# Start
./dev-kind.sh start
```

## Troubleshooting

### Cluster Won't Start

```bash
# Check if port is already in use
lsof -i :8001
lsof -i :5555

# Delete and recreate
./dev-kind.sh destroy
./dev-kind.sh start
```

### Pods CrashLooping

```bash
# Check logs
./dev-kind.sh logs api

# Check pod events
kubectl describe pod -n vexxy-premium <pod-name>

# Check if image loaded
docker exec -it vexxy-control-plane crictl images | grep vexxy-premium
```

### Database Connection Issues

```bash
# Check if postgres is ready
kubectl get pods -n vexxy-premium -l app=postgres

# Test connection from API pod
./dev-kind.sh shell api
# Inside pod:
nc -zv postgres.vexxy-premium.svc.cluster.local 5432
```

### Clean Slate

```bash
# Nuclear option - delete everything and start fresh
./dev-kind.sh destroy
./dev-kind.sh start
```

## Migrating from Docker Compose

If you were using `./dev.sh` (Docker Compose):

```bash
# Stop old setup
./dev.sh down

# Start new setup
./dev-kind.sh start

# Your data is lost (fresh database)
# Re-run any setup scripts you need
```

## Production Deployment

This kind setup is for **development only**. For production:

1. Use a real Kubernetes cluster (GKE, EKS, AKS, etc.)
2. Use proper secrets management (not plaintext passwords)
3. Use persistent volumes with proper storage classes
4. Set resource limits appropriately
5. Enable monitoring and logging
6. Use ingress controller instead of NodePort

But the manifests in `k8s/` are a great starting point!

## FAQ

**Q: Can I still use Docker Compose?**
A: Yes, but it's not recommended. The networking is messy and you'll have ZAP connectivity issues.

**Q: Do I need to keep port-forwarding to ZAP?**
A: No! ZAP is in the same cluster, so services can reach it at `owasp-zap.security.svc.cluster.local:8080`

**Q: How do I access the API from outside?**
A: kind maps ports - just use `http://localhost:8001`

**Q: Can I run multiple instances?**
A: Not easily - kind cluster names would conflict. Use separate kind clusters with different names.

**Q: How much resources does this use?**
A: About the same as Docker Compose. kind is just Docker containers running K8s.

## Next Steps

- Customize `k8s/configmap.yaml` for your environment
- Add monitoring (Prometheus/Grafana)
- Set up CI/CD to build and push images
- Add ingress for external access
- Configure autoscaling for workers
