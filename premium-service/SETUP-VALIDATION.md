# Premium Service Kubernetes Setup - Validation Guide

## Overview

The Kubernetes configuration setup has been completely refactored to be **reliable** and **idempotent**. This document explains the new architecture and how to validate it.

## What Changed

### 1. New Entrypoint Script (`docker-entrypoint.sh`)

All containers now use a standardized entrypoint script that:
- ✅ Creates `/root/.kube` directory if it doesn't exist
- ✅ Copies kubeconfig from the temporary mount location (`/tmp/kubeconfig/config`)
- ✅ Sets proper permissions (600) on the kubeconfig file
- ✅ Validates kubectl and helm are installed
- ✅ Tests cluster connectivity (non-blocking, warns if cluster unavailable)
- ✅ Provides detailed logging for troubleshooting

### 2. Updated Docker Configuration

**Dockerfile Changes:**
- Installs kubectl, helm, and Docker CLI in all containers
- Copies and sets up the entrypoint script
- Uses `ENTRYPOINT` to ensure setup runs before any command

**docker-compose.yml Changes:**
- Mounts `${HOME}/.kube` directory to `/tmp/kubeconfig` (not directly to `/root/.kube/config`)
- Removed `KUBECONFIG` environment variable (now set by entrypoint)
- Added healthchecks for all services
- Consistent configuration across API, Worker, and Flower services

### 3. Validation Script

New `validate-setup.sh` script checks:
- Container running status
- kubectl installation and version
- helm installation and version
- Kubeconfig file presence and permissions
- Cluster connectivity
- Docker CLI availability (for worker)

## How to Test

### Step 1: Rebuild and Start Services

```bash
cd /home/user/vexxy-enterprise/premium-service

# Stop existing containers
docker-compose down

# Rebuild and start (this will use the new entrypoint)
docker-compose up -d --build

# Watch the logs to see the entrypoint output
docker-compose logs -f
```

### Step 2: Check Entrypoint Logs

Look for output like this in each container:

```
=== Vexxy Premium Service Entrypoint ===
[INFO] Setting up Kubernetes configuration...
[INFO] Found kubeconfig at /tmp/kubeconfig/config
[INFO] Kubeconfig copied to /root/.kube/config
[INFO] kubectl version: v1.28.x
[SUCCESS] kubectl can connect to cluster
[INFO] Verifying required tools...
[OK] kubectl is installed
[OK] helm is installed: v3.x.x
[INFO] Environment setup complete
=========================================
```

### Step 3: Run Validation Script

```bash
# Make sure the script is executable
chmod +x validate-setup.sh

# Run the validation
./validate-setup.sh
```

Expected output:
```
==================================================
   Vexxy Premium Service Setup Validation
==================================================

Checking API (vexxy-premium-api)...
----------------------------------------
✓ Container is running
✓ kubectl is installed
  Version: v1.28.x
✓ helm is installed
  Version: v3.x.x
✓ Kubeconfig exists at /root/.kube/config
  Permissions: 600
✓ kubectl can connect to cluster
✓ KUBECONFIG environment variable is set
  Path: /root/.kube/config

Checking Worker (vexxy-premium-worker)...
----------------------------------------
✓ Container is running
✓ kubectl is installed
✓ helm is installed
✓ Kubeconfig exists at /root/.kube/config
✓ kubectl can connect to cluster
✓ Docker CLI is installed

Checking Flower (vexxy-premium-flower)...
----------------------------------------
✓ Container is running
✓ kubectl is installed
✓ helm is installed
✓ Kubeconfig exists at /root/.kube/config
```

### Step 4: Manual Verification

Verify kubectl works in each container:

```bash
# Test API container
docker exec vexxy-premium-api kubectl get nodes
docker exec vexxy-premium-api kubectl version

# Test Worker container
docker exec vexxy-premium-worker kubectl get nodes
docker exec vexxy-premium-worker helm version

# Test Flower container
docker exec vexxy-premium-flower kubectl cluster-info
```

### Step 5: Verify Idempotency

Restart containers multiple times to ensure setup is idempotent:

```bash
# Restart API container
docker-compose restart api

# Check logs - should show successful setup again
docker-compose logs api | grep -A 20 "Entrypoint"

# Restart all services
docker-compose restart

# Validate again
./validate-setup.sh
```

## Troubleshooting

### Issue: "No kubeconfig found"

**Cause:** The `${HOME}/.kube/config` file doesn't exist on the host.

**Solution:**
```bash
# Check if kubeconfig exists on host
ls -la ~/.kube/config

# If using a different kubeconfig location, update docker-compose.yml:
# Change: ${HOME}/.kube:/tmp/kubeconfig:ro
# To: /path/to/your/.kube:/tmp/kubeconfig:ro
```

### Issue: "kubectl cannot connect to cluster"

**Cause:** Cluster is not running or kubeconfig is invalid.

**Solution:**
```bash
# Test on host first
kubectl cluster-info

# If host works but container doesn't, check kubeconfig:
docker exec vexxy-premium-api cat /root/.kube/config

# Compare with host:
cat ~/.kube/config
```

### Issue: "Directory not found" errors

**Cause:** Entrypoint script didn't run or failed.

**Solution:**
```bash
# Check container logs
docker-compose logs api | grep -i error

# Verify entrypoint script exists
docker exec vexxy-premium-api ls -la /usr/local/bin/docker-entrypoint.sh

# Manually run entrypoint to see errors
docker exec vexxy-premium-api /usr/local/bin/docker-entrypoint.sh echo "test"
```

### Issue: Permission denied on kubeconfig

**Cause:** Kubeconfig permissions are too restrictive.

**Solution:**
```bash
# Check permissions on host
ls -la ~/.kube/config

# Should be readable (typically 600 or 644)
# If needed, fix permissions:
chmod 600 ~/.kube/config
```

## Benefits of New Approach

1. **Idempotent**: Can restart containers multiple times without issues
2. **Reliable**: Proper directory and file creation in the right order
3. **Observable**: Detailed logging shows exactly what's happening
4. **Consistent**: Same setup process across all containers
5. **Flexible**: Easy to update or customize the setup process
6. **Debuggable**: Validation script helps identify issues quickly

## Integration with OWASP ZAP and Kubescape

This refactored setup ensures that:

- **OWASP ZAP scans** can reliably access Kubernetes cluster for context
- **Kubescape** has proper kubectl access for security scanning
- Both tools run consistently whether in API or Worker containers
- Setup survives container restarts and rebuilds

## Next Steps

1. Run the validation script after every deployment
2. Monitor entrypoint logs during container startup
3. Add custom validation checks as needed
4. Update the entrypoint script for additional tools or setup steps

---

**Last Updated:** 2025-11-15
**Version:** 1.0.0
