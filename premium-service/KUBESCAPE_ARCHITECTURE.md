# Kubescape-Based Architecture

## Overview

The premium VEX generation service now uses **Kubescape** for runtime analysis and VEX generation. This replaces the previous manual approach with Tracee profiling and custom reachability analysis.

## Why Kubescape?

Kubescape is **the official tool** for runtime vulnerability analysis and VEX generation in Kubernetes environments. It provides:

1. **Automatic VEX Generation**: Creates OpenVEX documents based on runtime behavior
2. **Filtered SBOMs**: Generates SBOMs containing only components actually used at runtime (relevancy analysis)
3. **Reachability Analysis**: Determines which vulnerabilities are reachable based on actual execution
4. **High Confidence**: Uses eBPF-based runtime monitoring (similar to Tracee, but integrated)

## Architecture Changes

### Before (Manual Approach)

```
1. Deploy container in K8s Job
2. Add Tracee profiler sidecar
3. Wait for execution
4. Parse Tracee logs manually
5. Fetch SBOM from backend (mock data)
6. Manually analyze reachability
7. Generate VEX document from scratch
```

**Problems:**
- Mock SBOM data
- Duplicates Kubescape functionality
- Less accurate reachability analysis
- More complex codebase

### After (Kubescape Approach)

```
1. Ensure Kubescape is installed
2. Deploy workload as Deployment (not Job)
3. Kubescape automatically:
   - Monitors runtime behavior
   - Generates filtered SBOM
   - Performs reachability analysis
   - Creates VEX document
4. Extract CRDs from Kubescape
5. Process and return results
```

**Benefits:**
- Real SBOM and vulnerability data
- Official Kubescape analysis (high confidence)
- Simpler codebase (removed 500+ lines)
- Uses production-grade tooling

## New Workflow

### Phase 1: Kubescape Installation

```python
# Check if Kubescape is installed
if not kubescape_service.is_kubescape_installed():
    # Install via Helm
    kubescape_service.install_kubescape()
```

Kubescape is installed once per cluster with these capabilities:
- `relevancy: enable` - Generate filtered SBOMs
- `vulnerabilityScan: enable` - Scan for vulnerabilities
- `generateVEX: true` - Create VEX documents

### Phase 2: Deploy Workload

```python
deployment_name = kubescape_service.deploy_workload_for_analysis(
    job_id=job_id,
    image_ref="ghcr.io/owner/repo",
    image_digest="sha256:abc123...",
    job_config={
        "analysis_duration": 300,  # 5 minutes
        "environment": {"PORT": "8080"},
        "command": ["/bin/sh", "-c", "sleep 600"]
    }
)
```

**Key difference:** We deploy a **Deployment** (not a Job) because Kubescape's nodeAgent monitors Deployments.

### Phase 3: Runtime Analysis

```python
# Wait for Kubescape to analyze the workload
# During this time, Kubescape:
# - Monitors system calls (eBPF)
# - Tracks library usage
# - Determines reachable code paths
# - Generates filtered SBOM
# - Creates VEX statements

success = kubescape_service.wait_for_kubescape_analysis(
    deployment_name=deployment_name,
    timeout_seconds=420  # analysis_duration + buffer
)
```

### Phase 4: Extract Results

```python
# Extract Kubescape CRDs
vex, filtered_sbom = kubescape_service.extract_kubescape_analysis(
    deployment_name=deployment_name,
    image_digest=image_digest
)
```

**CRDs extracted:**
1. **OpenVulnerabilityExchangeContainer** - Runtime VEX document
2. **SBOMSyftFiltered** - Filtered SBOM with only relevant components

### Phase 5: Process Results

```python
# Enhance VEX with VEXxy metadata
vex_document = {
    **kubescape_vex,
    "vexxy_metadata": {
        "job_id": job_id,
        "analysis_method": "kubescape_runtime",
        "confidence_level": "high"
    }
}

# Generate summary
summary = {
    "total_cves_analyzed": len(vex_document["statements"]),
    "not_affected": count_not_affected(vex_document),
    "affected": count_affected(vex_document),
    "total_components_in_image": len(filtered_sbom["components"])
}
```

## Kubescape CRD Structure

### OpenVulnerabilityExchangeContainer

```yaml
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: OpenVulnerabilityExchangeContainer
metadata:
  name: ghcr-io-owner-repo-sha256-abc123
  namespace: kubescape
spec:
  "@context": "https://openvex.dev/ns/v0.2.0"
  "@id": "https://kubescape.io/vex/..."
  author: "Kubescape"
  timestamp: "2025-11-13T10:00:00Z"
  version: 1
  statements:
    - vulnerability:
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
        name: "CVE-2024-12345"
      status: "not_affected"
      justification: "vulnerable_code_not_in_execute_path"
      products:
        - "@id": "pkg:oci/repo@sha256:abc123"
```

### SBOMSyftFiltered

```yaml
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: SBOMSyftFiltered
metadata:
  name: ghcr-io-owner-repo-sha256-abc123
  namespace: kubescape
spec:
  bomFormat: "CycloneDX"
  specVersion: "1.4"
  components:
    - name: "libssl"
      version: "1.1.1"
      type: "library"
      purl: "pkg:deb/debian/libssl@1.1.1"
      # Only components actually used at runtime
```

## Deployment Requirements

### 1. Kubernetes Cluster

- Kubernetes 1.21+ required
- `kubectl` access from premium service worker
- Cluster supports eBPF (for Kubescape nodeAgent)

### 2. Kubescape Installation

```bash
# Option 1: Let service auto-install
# The service will detect and install Kubescape automatically

# Option 2: Manual pre-installation
helm repo add kubescape https://kubescape.github.io/helm-charts
helm repo update

helm install kubescape kubescape/kubescape-operator \
  -n kubescape \
  --create-namespace \
  -f kubescape-values.yaml \
  --wait
```

### 3. Required Permissions

The service account needs permissions to:
- Create Deployments in sandbox namespace
- Read CRDs in kubescape namespace
- Install Helm charts (if auto-installing)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vexxy-premium-service
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["create", "get", "delete", "list"]
  - apiGroups: ["spdx.softwarecomposition.kubescape.io"]
    resources: ["openvulnerabilityexchangecontainers", "sbomsyftfiltereds"]
    verbs: ["get", "list"]
```

## Configuration

### Environment Variables

```bash
# Kubernetes
K8S_IN_CLUSTER=true  # Run inside cluster
K8S_SANDBOX_NAMESPACE=vexxy-sandbox  # Namespace for analysis workloads

# Sandbox Resource Limits
SANDBOX_CPU_LIMIT=2000m
SANDBOX_MEMORY_LIMIT=4Gi
SANDBOX_CPU_REQUEST=1000m
SANDBOX_MEMORY_REQUEST=2Gi

# Analysis
DEFAULT_ANALYSIS_DURATION=300  # 5 minutes
K8S_JOB_TTL_SECONDS=600  # Cleanup after 10 minutes
```

### Docker Compose

```yaml
worker:
  volumes:
    - ~/.kube/config:/root/.kube/config:ro  # For local development
  environment:
    K8S_IN_CLUSTER: "false"  # Use local kubeconfig
```

## Testing

### Test with Real Images

```bash
# Start services
cd premium-service
docker-compose up -d

# Submit analysis
curl -X POST http://localhost:8001/api/v1/analysis/submit \
  -H "Content-Type: application/json" \
  -d '{
    "image_ref": "ghcr.io/owner/repo",
    "image_digest": "sha256:abc123...",
    "config": {
      "analysis_duration": 300
    }
  }'

# Check status
curl http://localhost:8001/api/v1/analysis/{job_id}/status

# Get results
curl http://localhost:8001/api/v1/analysis/{job_id}/results
```

### Expected Results

After 5-10 minutes:
- **Status**: `COMPLETE`
- **VEX Document**: OpenVEX with reachability statements
- **Filtered SBOM**: Only components used at runtime
- **Summary**:
  - Total CVEs analyzed
  - Not affected (vulnerable code not executed)
  - Affected (requires action)

## Troubleshooting

### Kubescape Not Found

```bash
# Check if Kubescape namespace exists
kubectl get namespace kubescape

# Check Kubescape pods
kubectl get pods -n kubescape

# Check CRDs
kubectl get crd | grep kubescape
```

### No VEX Generated

```bash
# Check if workload is running
kubectl get deployments -n vexxy-sandbox

# Check Kubescape logs
kubectl logs -n kubescape -l app.kubernetes.io/name=kubevuln --tail=100

# Check nodeAgent logs
kubectl logs -n kubescape -l app.kubernetes.io/name=node-agent --tail=100
```

### CRDs Not Found

```bash
# List all VEX documents
kubectl get openvulnerabilityexchangecontainers -n kubescape

# List all filtered SBOMs
kubectl get sbomsyftfiltereds -n kubescape

# Describe specific CRD
kubectl describe openvulnerabilityexchangecontainer <name> -n kubescape
```

## Migration Notes

### What Was Removed

- ✅ `tasks_impl.py` - Old manual profiling logic (now `tasks_impl_kubescape.py`)
- ✅ Tracee sidecar from sandbox jobs
- ✅ Mock SBOM service usage
- ✅ Manual reachability analysis code
- ✅ Custom VEX generation logic

### What Was Added

- ✅ `services/kubescape.py` - Kubescape integration service
- ✅ `workers/tasks_impl_kubescape.py` - Kubescape-based task implementation
- ✅ Auto-install Kubescape via Helm
- ✅ CRD extraction logic
- ✅ Deployment-based workloads (instead of Jobs)

### What Stayed

- ✅ API endpoints (same interface)
- ✅ Database models (same schema)
- ✅ Evidence storage
- ✅ Job status tracking
- ✅ Celery task queue

## Performance

### Analysis Time

- **Deployment creation**: 10-15 seconds
- **Workload ready**: 20-30 seconds
- **Runtime analysis**: 5-10 minutes (configurable)
- **CRD extraction**: 5-10 seconds
- **Total**: ~6-11 minutes per analysis

### Resource Usage

Per analysis job:
- **CPU**: 1-2 cores
- **Memory**: 2-4 GB
- **Storage**: ~500 MB (evidence)

Kubescape overhead:
- **CPU**: 200m per node (nodeAgent)
- **Memory**: 512 MB per node
- **Storage**: ~2 GB (vulnerability database)

## Future Enhancements

1. **Custom Test Scripts**: Execute user-provided tests during runtime analysis
2. **OWASP ZAP Integration**: Add fuzzing for web applications
3. **Multi-image Analysis**: Compare VEX across image versions
4. **Scheduled Re-analysis**: Periodic VEX updates
5. **Advanced Filtering**: User-controlled relevancy thresholds

## References

- [Kubescape Documentation](https://kubescape.io/docs/)
- [OpenVEX Specification](https://openvex.dev/)
- [Kubescape Helm Chart](https://github.com/kubescape/helm-charts)
- [SPDX CRDs](https://github.com/kubescape/storage/tree/master/pkg/apis/softwarecomposition)
