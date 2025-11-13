# Premium VEX Generation Service - Integration Plan

**Date:** November 13, 2025
**Status:** Planning Phase
**Target:** Rapid MVP in 4-6 weeks

---

## Executive Summary

Transform existing GitHub Actions VEX workflows into a standalone premium service that provides **automated reachability-based VEX generation** - your Ultimate tier competitive moat.

**Value Prop:** "The only platform that proves vulnerabilities are unreachable through runtime evidence"

**Current Assets:**
- ✅ Production-ready VEX analysis workflows (build + runtime)
- ✅ Kubescape integration for runtime analysis
- ✅ eBPF profiling setup (Tracee/Falco patterns)
- ✅ OWASP ZAP fuzzing integration
- ✅ Filtered SBOM extraction
- ✅ VEX consolidation logic

**Gap:** These run in GitHub Actions, not as an on-demand premium service

**Solution:** Extract workflow logic → Build standalone service → Integrate with vexxy backend

---

## Architecture Overview

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────┐
│                      VEXxy Core (Open Source)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Vulnerability│  │ VEX Statement│  │  SBOM        │          │
│  │ Management   │  │ Management   │  │  Management  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                  │                  │                  │
│         └──────────────────┴──────────────────┘                  │
│                           │                                      │
│                    API Gateway (Premium)                         │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│           Premium VEX Generation Service (Enterprise)            │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    Analysis Orchestrator                    │ │
│  │  • Job Queue (Celery/Bull)                                 │ │
│  │  • Analysis State Machine                                  │ │
│  │  • Priority Queue (paying customers first)                 │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            │                                     │
│         ┌──────────────────┼──────────────────┐                 │
│         ▼                  ▼                  ▼                  │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐           │
│  │  Sandbox    │   │  Runtime    │   │   Security  │           │
│  │  Manager    │   │  Profiler   │   │   Fuzzer    │           │
│  │             │   │             │   │             │           │
│  │ • K8s Job   │   │ • eBPF      │   │ • OWASP ZAP │           │
│  │ • gVisor    │   │ • Tracee    │   │ • Custom    │           │
│  │ • Timeout   │   │ • Syscalls  │   │   Tests     │           │
│  └─────────────┘   └─────────────┘   └─────────────┘           │
│         │                  │                  │                  │
│         └──────────────────┼──────────────────┘                  │
│                            ▼                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              Reachability Analyzer                         │ │
│  │  • CVE → Code Path Mapping                                 │ │
│  │  • Execution Coverage Analysis                             │ │
│  │  • Evidence Collection                                     │ │
│  │  • Confidence Scoring                                      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            │                                     │
│                            ▼                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │               VEX Document Generator                       │ │
│  │  • Automated VEX statements                                │ │
│  │  • Evidence attachment                                     │ │
│  │  • Cryptographic signing                                   │ │
│  │  • OpenVEX/CycloneDX output                                │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            │                                     │
└────────────────────────────┼─────────────────────────────────────┘
                             │
                             ▼
                  ┌────────────────────┐
                  │   Object Storage   │
                  │  (S3/MinIO/GCS)    │
                  │  • Analysis logs   │
                  │  • Evidence files  │
                  │  • VEX documents   │
                  └────────────────────┘
```

---

## Component Breakdown

### 1. Analysis Orchestrator

**Purpose:** Manage analysis job lifecycle

**Tech Stack:**
- **Queue:** Celery (you're already using it) or Bull (if switching to Node.js workers)
- **State Store:** Redis (you have this)
- **Database:** PostgreSQL (track analysis history, quota)

**Key Features:**
- Job submission API
- Priority queue (Ultimate tier → Pro → Standard)
- Quota enforcement (50-200 analyses/month per tier)
- Status tracking (queued → running → analyzing → complete → failed)
- Retry logic with backoff
- Analysis history and caching (don't re-analyze same image SHA)

**API Endpoints:**
```python
POST   /api/v1/premium/analysis/submit
GET    /api/v1/premium/analysis/{job_id}/status
GET    /api/v1/premium/analysis/{job_id}/results
DELETE /api/v1/premium/analysis/{job_id}/cancel
GET    /api/v1/premium/analysis/quota
```

**Implementation Path:**
1. Start with simple FastAPI service (reuse your backend stack)
2. Celery workers for heavy lifting
3. PostgreSQL for persistence
4. Redis for job queue + caching

---

### 2. Sandbox Manager

**Purpose:** Isolate and execute container images safely

**Critical Requirements:**
- ✅ Isolation (prevent sandbox escape)
- ✅ Resource limits (CPU, memory, network)
- ✅ Timeout enforcement (max 15 minutes per analysis)
- ✅ Network control (optional internet access)
- ✅ Cleanup (no leftover containers)

**Technology Options:**

#### Option A: Kubernetes Jobs (Like your workflow) ✅ RECOMMENDED
**Pros:**
- You already have the pattern in `vex-analysis.yml`
- Strong isolation (separate namespaces)
- Built-in resource limits
- Cloud-agnostic

**Cons:**
- Requires K8s cluster access
- Slower startup (5-15 seconds per job)

**Implementation:**
```yaml
# Sandbox job template
apiVersion: batch/v1
kind: Job
metadata:
  name: vex-analysis-{job_id}
  namespace: vexxy-sandbox
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 600
  template:
    spec:
      runtimeClassName: gvisor  # Optional: extra isolation
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: sandbox
        image: {customer_image}
        resources:
          limits:
            cpu: "2"
            memory: "4Gi"
          requests:
            cpu: "1"
            memory: "2Gi"
      - name: profiler
        image: ghcr.io/aquasecurity/tracee:latest
        securityContext:
          privileged: true  # Required for eBPF
      - name: fuzzer
        image: owasp/zap2docker-stable
```

#### Option B: Docker-in-Docker (Simpler for MVP)
**Pros:**
- Faster development
- No K8s required
- Good for early testing

**Cons:**
- Less isolation (security risk)
- Harder to scale
- Privilege requirements

**Not recommended for production Ultimate tier**

---

### 3. Runtime Profiler

**Purpose:** Capture what code actually executes during runtime

**Tech Stack:**
- **eBPF tracer:** Tracee (you're already familiar from workflows)
- **Syscall monitor:** Capture syscalls, file access, network activity
- **Code coverage:** Language-specific tools (gcov, coverage.py, nyc)

**Workflow:**
1. Start container with profiler attached
2. Execute test suite (user-provided or auto-generated)
3. Capture:
   - Syscalls made
   - Files accessed
   - Network connections
   - Loaded libraries
   - Executed functions (if debug symbols available)
4. Generate execution map

**Example Output:**
```json
{
  "image": "ghcr.io/example/app@sha256:abc123",
  "analysis_id": "abc-123-def",
  "duration_seconds": 180,
  "execution_profile": {
    "syscalls": ["read", "write", "socket", "connect"],
    "files_accessed": ["/app/main.py", "/app/lib/utils.py"],
    "network_connections": ["8.8.8.8:443"],
    "loaded_libraries": ["libc.so.6", "libssl.so.1.1"],
    "functions_executed": ["main", "handle_request", "validate_input"]
  },
  "code_coverage": {
    "total_lines": 5000,
    "executed_lines": 1200,
    "coverage_percent": 24.0,
    "files": [
      {"path": "/app/main.py", "coverage": 85.0},
      {"path": "/app/lib/crypto.py", "coverage": 0.0}
    ]
  }
}
```

**Integration with Tracee:**
```bash
# Run in sandbox
tracee --output json \
  --output option:parse-arguments \
  --trace comm=myapp \
  --trace follow \
  > tracee-output.json
```

---

### 4. Security Fuzzer

**Purpose:** Exercise application with realistic traffic to maximize code coverage

**Tech Stack:**
- **Web apps:** OWASP ZAP (you have this)
- **APIs:** Custom HTTP fuzzer or RESTler
- **gRPC:** grpc_cli or custom fuzzer

**Workflow:**
1. Detect application type (web, API, gRPC, CLI)
2. Run appropriate fuzzer:
   - **Web:** ZAP spider + active scan (low intensity)
   - **API:** Send requests to all discovered endpoints
   - **CLI:** Execute with various inputs
3. Collect responses and errors
4. Feed into profiler for coverage analysis

**Example ZAP Integration:**
```python
from zapv2 import ZAPv2

zap = ZAPv2(apikey='your-api-key', proxies={'http': 'http://localhost:8080'})

# Spider the application
zap.spider.scan(target_url)
while int(zap.spider.status()) < 100:
    time.sleep(2)

# Passive scan (safe, no attacks)
zap.pscan.enable_all_scanners()

# Active scan (optional, configurable intensity)
zap.ascan.scan(target_url, recurse=True, inscopeonly=True)
while int(zap.ascan.status()) < 100:
    time.sleep(5)

# Get alerts (findings)
alerts = zap.core.alerts(baseurl=target_url)
```

**User-Provided Tests:**
Allow customers to provide their own test scripts for better coverage:
```yaml
# User configuration
analysis:
  image: ghcr.io/mycompany/api:latest
  test_script: |
    #!/bin/bash
    # Custom test suite
    curl http://localhost:8080/health
    curl http://localhost:8080/api/users
    curl -X POST http://localhost:8080/api/login -d '{"user":"test","pass":"test"}'
  environment:
    DATABASE_URL: "sqlite:///test.db"
  ports:
    - 8080
```

---

### 5. Reachability Analyzer

**Purpose:** Determine if vulnerable code is reachable based on execution profile

**Core Logic:**
```python
def analyze_reachability(cve: CVE, sbom: SBOM, execution_profile: ExecutionProfile) -> ReachabilityResult:
    """
    Determine if CVE is reachable based on runtime evidence
    """
    # 1. Find vulnerable component in SBOM
    vuln_component = sbom.find_component(cve.package, cve.version)
    if not vuln_component:
        return ReachabilityResult(status="not_applicable", confidence=1.0)

    # 2. Map CVE to code location
    vuln_files = get_vulnerable_files(cve, vuln_component)
    if not vuln_files:
        return ReachabilityResult(status="unknown", confidence=0.5,
                                  reason="Cannot map CVE to code files")

    # 3. Check if vulnerable code was executed
    executed_files = execution_profile.files_accessed

    if any(vf in executed_files for vf in vuln_files):
        # Vulnerable code WAS executed
        return ReachabilityResult(
            status="affected",
            confidence=0.9,
            reason="Vulnerable code executed during runtime analysis",
            evidence={
                "vulnerable_files": vuln_files,
                "executed_files": executed_files,
                "execution_trace": execution_profile.get_trace(vuln_files)
            }
        )
    else:
        # Vulnerable code was NOT executed
        return ReachabilityResult(
            status="not_affected",
            justification="vulnerable_code_not_in_execute_path",
            confidence=0.85,
            reason="Vulnerable code exists but was not executed during comprehensive testing",
            evidence={
                "vulnerable_files": vuln_files,
                "executed_files": executed_files,
                "coverage_percent": execution_profile.code_coverage.coverage_percent,
                "test_duration": execution_profile.duration_seconds
            }
        )

class ReachabilityResult:
    status: str  # "affected" | "not_affected" | "under_investigation" | "unknown"
    justification: str  # OpenVEX justification codes
    confidence: float  # 0.0-1.0
    reason: str
    evidence: dict
```

**Confidence Scoring:**
- **High (0.8-1.0):** Vulnerable file directly executed or definitely not executed
- **Medium (0.5-0.8):** Indirect evidence (library loaded but function not called)
- **Low (0.0-0.5):** Insufficient evidence (low test coverage, no debug symbols)

**VEX Justification Mapping:**
```python
JUSTIFICATIONS = {
    "vulnerable_code_not_in_execute_path": {
        "confidence_threshold": 0.7,
        "description": "Vulnerable code exists but is not executed based on runtime analysis"
    },
    "vulnerable_code_not_present": {
        "confidence_threshold": 0.9,
        "description": "Vulnerable code was removed or patched"
    },
    "inline_mitigations_already_exist": {
        "confidence_threshold": 0.8,
        "description": "Mitigations detected in runtime behavior"
    }
}
```

---

### 6. VEX Document Generator

**Purpose:** Create OpenVEX documents with reachability evidence

**Output Format:**
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://vexxy.dev/vex/reachability/abc-123-def",
  "author": "VEXxy Premium Analysis Service",
  "timestamp": "2025-11-13T10:30:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
        "name": "CVE-2024-12345",
        "description": "Buffer overflow in libfoo"
      },
      "products": [
        {
          "@id": "pkg:oci/myapp@sha256:abc123?repository_url=ghcr.io/example/myapp"
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "The vulnerable function libfoo_process() exists in the binary but was not executed during comprehensive runtime analysis covering 85% of application code paths.",
      "action_statement": "No action required. Continue monitoring for changes in code execution patterns.",
      "vexxy_evidence": {
        "analysis_id": "abc-123-def",
        "analysis_date": "2025-11-13T10:00:00Z",
        "confidence_score": 0.87,
        "runtime_profile": {
          "test_duration_seconds": 180,
          "code_coverage_percent": 85.0,
          "tests_executed": ["health_check", "api_endpoints", "authentication_flow"],
          "vulnerable_files": ["/usr/lib/libfoo.so.1"],
          "executed_files": ["/app/main", "/app/handlers", "/usr/lib/libssl.so"],
          "vulnerable_functions": ["libfoo_process"],
          "executed_functions": ["main", "handle_request", "validate_input"]
        },
        "fuzzing_results": {
          "tool": "OWASP ZAP",
          "requests_sent": 1250,
          "endpoints_discovered": 25,
          "code_paths_triggered": 340
        },
        "syscall_analysis": {
          "tool": "Tracee",
          "syscalls_captured": 15230,
          "unique_syscalls": 45,
          "suspicious_behavior": false
        }
      }
    }
  ]
}
```

**Key Features:**
- Standard OpenVEX format (interoperable)
- Custom `vexxy_evidence` field (rich context)
- Confidence scores (transparency)
- Actionable statements
- Cryptographic signing (Sigstore/Cosign)

---

## Integration with VEXxy Core

### API Flow

```
┌─────────────┐
│   VEXxy UI  │
└──────┬──────┘
       │ 1. User requests premium analysis
       ▼
┌──────────────────┐
│  VEXxy Backend   │ (FastAPI)
│  ┌────────────┐  │
│  │ Analysis   │  │ 2. Check tier & quota
│  │ Controller │  │ 3. Create analysis request
│  └────────────┘  │
└──────┬───────────┘
       │ 4. POST /premium/analysis/submit
       ▼
┌──────────────────────────────┐
│  Premium VEX Service         │
│  ┌────────────────────────┐  │
│  │ Orchestrator           │  │ 5. Validate & queue job
│  └────────────────────────┘  │
│           │                  │
│           ▼                  │
│  ┌────────────────────────┐  │
│  │ Celery Worker          │  │ 6. Process async
│  │  - Sandbox setup       │  │
│  │  - Runtime profiling   │  │
│  │  - Fuzzing             │  │
│  │  - Reachability        │  │
│  │  - VEX generation      │  │
│  └────────────────────────┘  │
│           │                  │
└───────────┼──────────────────┘
            │ 7. Webhook callback
            ▼
┌──────────────────┐
│  VEXxy Backend   │ 8. Store results
│  ┌────────────┐  │ 9. Update VEX statements
│  │ VEX Store  │  │ 10. Notify user
│  └────────────┘  │
└──────────────────┘
```

### Database Schema Extensions

```sql
-- Premium analysis jobs
CREATE TABLE premium_analysis_jobs (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    image_ref TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    sbom_id UUID REFERENCES sboms(id),

    -- Job status
    status VARCHAR(50) NOT NULL, -- queued, running, analyzing, complete, failed, cancelled
    priority INTEGER DEFAULT 0,

    -- Configuration
    config JSONB NOT NULL, -- Analysis settings (tests, fuzzing options, etc.)

    -- Results
    execution_profile JSONB,
    reachability_results JSONB,
    generated_vex_id UUID REFERENCES vex_documents(id),

    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,

    -- Billing
    billed_at TIMESTAMP,
    cost_credits INTEGER DEFAULT 1,

    INDEX idx_org_status (organization_id, status),
    INDEX idx_image (image_digest),
    INDEX idx_created (created_at DESC)
);

-- Quota tracking
CREATE TABLE premium_analysis_quota (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id),
    tier VARCHAR(50) NOT NULL, -- ultimate, enterprise_plus

    -- Quota limits
    monthly_limit INTEGER NOT NULL,
    extra_credits INTEGER DEFAULT 0,

    -- Usage tracking
    current_period_start DATE NOT NULL,
    current_period_usage INTEGER DEFAULT 0,
    total_usage INTEGER DEFAULT 0,

    updated_at TIMESTAMP DEFAULT NOW()
);

-- Analysis evidence (for audit trail)
CREATE TABLE analysis_evidence (
    id UUID PRIMARY KEY,
    analysis_job_id UUID NOT NULL REFERENCES premium_analysis_jobs(id),

    evidence_type VARCHAR(50) NOT NULL, -- execution_trace, syscall_log, fuzzing_results
    evidence_data JSONB NOT NULL,

    -- Storage reference (for large files)
    storage_path TEXT, -- S3/GCS URL
    file_size BIGINT,

    created_at TIMESTAMP DEFAULT NOW(),

    INDEX idx_job (analysis_job_id)
);
```

### Authentication & Authorization

```python
# In VEXxy backend
from fastapi import Depends, HTTPException, status
from app.models import Organization, User

async def check_premium_tier(
    org: Organization = Depends(get_current_org)
) -> Organization:
    """Verify organization has access to premium features"""
    if org.tier not in ["professional", "enterprise_plus", "ultimate"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Premium tier required for advanced analysis"
        )
    return org

async def check_analysis_quota(
    org: Organization = Depends(check_premium_tier)
) -> bool:
    """Check if organization has remaining analysis quota"""
    quota = await get_quota(org.id)

    if quota.current_period_usage >= quota.monthly_limit + quota.extra_credits:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Monthly analysis quota exceeded. Used: {quota.current_period_usage}, Limit: {quota.monthly_limit}"
        )

    return True

# API endpoint
@router.post("/premium/analysis/submit")
async def submit_premium_analysis(
    request: AnalysisRequest,
    org: Organization = Depends(check_premium_tier),
    _quota_check: bool = Depends(check_analysis_quota),
    db: Session = Depends(get_db)
):
    """Submit image for premium reachability analysis"""

    # Create job record
    job = PremiumAnalysisJob(
        id=uuid4(),
        organization_id=org.id,
        image_ref=request.image_ref,
        image_digest=request.image_digest,
        config=request.config,
        status="queued",
        priority=get_priority(org.tier)  # Ultimate > Enterprise > Pro
    )
    db.add(job)

    # Increment quota usage
    await increment_quota(org.id)

    # Submit to premium service
    response = await premium_service_client.submit_analysis({
        "job_id": str(job.id),
        "image_ref": request.image_ref,
        "image_digest": request.image_digest,
        "config": request.config,
        "callback_url": f"{settings.API_BASE_URL}/premium/analysis/callback"
    })

    db.commit()

    return {
        "job_id": job.id,
        "status": "queued",
        "estimated_duration_minutes": 15,
        "quota_remaining": quota.monthly_limit - quota.current_period_usage
    }
```

---

## Development Roadmap

### Phase 1: MVP Foundation (Weeks 1-2)

**Goal:** Prove the concept with minimal working version

#### Week 1: Core Infrastructure
- [x] Set up premium service repository structure
- [ ] FastAPI service skeleton
- [ ] Celery worker setup
- [ ] PostgreSQL schema for analysis jobs
- [ ] Redis for job queue
- [ ] Basic API endpoints (submit, status, results)

**Deliverable:** Service that can queue analysis jobs

#### Week 2: Sandbox + Basic Profiling
- [ ] K8s Job templates for sandbox
- [ ] Basic container execution (no profiling yet)
- [ ] Timeout enforcement
- [ ] Resource limits
- [ ] Simple execution logging

**Deliverable:** Can run container in sandbox and capture logs

**MVP Success Criteria:**
- Submit image → Sandbox executes → Returns execution log
- No VEX generation yet, just proof of sandboxing

---

### Phase 2: Runtime Analysis (Weeks 3-4)

**Goal:** Add runtime profiling and basic reachability analysis

#### Week 3: Profiling Integration
- [ ] Tracee sidecar container
- [ ] Syscall capture
- [ ] File access monitoring
- [ ] Network activity tracking
- [ ] Execution profile JSON output

**Deliverable:** Execution profile with file/syscall data

#### Week 4: Reachability Logic
- [ ] CVE → code file mapping (using SBOM)
- [ ] Basic reachability algorithm (file-based)
- [ ] Confidence scoring (simple version)
- [ ] Evidence collection

**Deliverable:** Reachability determination for CVEs

**Phase 2 Success Criteria:**
- Submit image with known CVE → Analysis determines if code is reachable
- Output includes evidence (files executed, syscalls)

---

### Phase 3: VEX Generation (Weeks 5-6)

**Goal:** Generate production-ready VEX documents

#### Week 5: VEX Document Creation
- [ ] OpenVEX template with evidence
- [ ] VEX statement generation from reachability results
- [ ] Impact and action statements
- [ ] VEX validation

**Deliverable:** Valid OpenVEX documents with reachability data

#### Week 6: Integration + UI
- [ ] Callback to vexxy backend
- [ ] Store VEX in main database
- [ ] Basic UI for viewing analysis results
- [ ] Quota enforcement
- [ ] Billing/usage tracking

**Deliverable:** End-to-end flow from UI to VEX document

**Phase 3 Success Criteria:**
- User can submit analysis via UI
- View results in vexxy interface
- VEX documents exported and usable

---

### Phase 4: Production Hardening (Weeks 7-8)

**Goal:** Make it production-ready for first customers

#### Week 7: Security + Reliability
- [ ] Sandbox security audit
- [ ] gVisor runtime for extra isolation
- [ ] Retry logic and error handling
- [ ] Monitoring and alerting (Prometheus)
- [ ] Analysis result caching (avoid re-running same image)

#### Week 8: Advanced Features
- [ ] User-provided test scripts
- [ ] OWASP ZAP fuzzing integration
- [ ] Code coverage analysis (language-specific)
- [ ] Comparison reports (image A vs B)
- [ ] Scheduled re-analysis

**Deliverable:** Production-ready Ultimate tier feature

**Phase 4 Success Criteria:**
- Design partner can use in production
- Security review passed
- 99% sandbox job success rate
- Average analysis time <10 minutes

---

### Phase 5: Scale + Optimization (Weeks 9-12)

**Goal:** Handle multiple customers at scale

- [ ] Multi-region sandbox clusters
- [ ] Auto-scaling based on queue depth
- [ ] Performance optimization (parallel analysis)
- [ ] Advanced ML for confidence scoring
- [ ] Integration with more fuzzers (RESTler, etc.)

---

## Technology Stack Summary

| Component | Technology | Justification |
|-----------|------------|---------------|
| **Service API** | FastAPI | You're already using it, async support |
| **Job Queue** | Celery + Redis | Proven, you have experience |
| **Database** | PostgreSQL | Main vexxy database |
| **Container Orchestration** | Kubernetes | Required for sandbox isolation |
| **Sandbox Runtime** | gVisor (optional) | Extra security layer |
| **eBPF Profiler** | Tracee | Open source, proven in your workflows |
| **Fuzzer** | OWASP ZAP | Web app fuzzing, free |
| **Object Storage** | MinIO (self-hosted) or S3 | Evidence storage |
| **Monitoring** | Prometheus + Grafana | Standard observability |
| **Secrets** | Vault or K8s Secrets | For customer API keys, etc. |

---

## Deployment Architecture

### Option A: Single-Cluster (MVP)
```
┌─────────────────────────────────────────┐
│         Main Kubernetes Cluster         │
│                                         │
│  ┌─────────────┐   ┌────────────────┐  │
│  │   VEXxy     │   │    Premium     │  │
│  │   Backend   │   │    Service     │  │
│  └─────────────┘   └────────────────┘  │
│                                         │
│  ┌──────────────────────────────────┐  │
│  │   Sandbox Namespace (isolated)    │  │
│  │  ┌──────┐  ┌──────┐  ┌──────┐   │  │
│  │  │ Job1 │  │ Job2 │  │ Job3 │   │  │
│  │  └──────┘  └──────┘  └──────┘   │  │
│  └──────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**Pros:** Simple, low cost
**Cons:** Sandbox shares cluster with prod (some risk)

### Option B: Dedicated Sandbox Cluster (Production)
```
┌──────────────────┐       ┌──────────────────────┐
│  Main Cluster    │       │  Sandbox Cluster     │
│                  │       │                      │
│  ┌───────────┐   │       │  ┌──────────────┐   │
│  │  VEXxy    │   │       │  │   Sandbox    │   │
│  │  Backend  ├───┼──────►│  │   Jobs Only  │   │
│  └───────────┘   │  API  │  └──────────────┘   │
│                  │       │                      │
│  ┌───────────┐   │       │  • gVisor runtime    │
│  │  Premium  │   │       │  • Network policies  │
│  │  Service  ├───┼──────►│  • Resource quotas   │
│  └───────────┘   │  K8s  │  • Auto-scaling      │
└──────────────────┘  API  └──────────────────────┘
```

**Pros:** Strong isolation, safer for production
**Cons:** More complex, higher cost (2x clusters)

**Recommendation:** Start with Option A for MVP, migrate to Option B for production

---

## Cost Analysis

### Infrastructure Costs (Monthly)

**MVP (Single Cluster):**
- K8s cluster: $200/month (3 nodes, e2-standard-4)
- Database: Included in main vexxy database
- Redis: Included
- Object storage: $20/month (1TB)
- **Total: ~$220/month**

**Production (Dedicated Sandbox):**
- Main cluster: $300/month
- Sandbox cluster: $400/month (auto-scaling 3-10 nodes)
- Object storage: $50/month (5TB)
- **Total: ~$750/month**

**Per-Analysis Costs:**
- Compute: ~$0.50 per analysis (10 min at $0.05/min)
- Storage: ~$0.02 per analysis (500MB avg)
- **Total: ~$0.52 per analysis**

**Margins:**
- Charge: $500-1000 per ad-hoc analysis
- Cost: ~$0.52
- **Gross margin: 99.9%** 🎉

**Monthly Plan:**
- Charge: $100K/year = $8.3K/month
- Includes: 100 analyses/month
- Cost: $52/month (100 * $0.52)
- Infrastructure: $750/month
- **Total cost: $802/month**
- **Gross margin: 90%**

---

## Go-to-Market Strategy

### Pricing (from your roadmap)

**Ultimate Tier:**
- **Annual:** $75K-150K/year
- **Includes:** 50-200 analyses/month
- **Overage:** $500-1000 per additional analysis

**Value Prop:**
"Prove vulnerabilities are unreachable with runtime evidence - not guesses"

### Sales Approach

**Design Partners (First 3 customers):**
- Offer 50% discount ($75K → $37.5K)
- In exchange for:
  - Detailed feedback
  - Case study
  - Logo permission
  - Reference calls

**Beta Pricing (Next 10 customers):**
- Offer 25% discount ($75K)
- Lock in price for 2 years
- Early adopter benefits

**General Availability:**
- Full price ($100K-150K based on scale)
- Volume discounts for multi-year

---

## Success Metrics

### Technical KPIs
- **Analysis success rate:** >95%
- **Average analysis time:** <10 minutes
- **Sandbox security:** Zero escapes
- **VEX accuracy:** >85% confidence scores

### Business KPIs
- **Month 3:** 1 design partner signed
- **Month 6:** 3 paying customers ($225K ARR)
- **Month 12:** 10 customers ($750K ARR)

### Product KPIs
- **Monthly analyses:** 500+ by Month 6
- **Code coverage avg:** >70%
- **Customer satisfaction:** >4.5/5

---

## Risks & Mitigations

### Risk 1: Sandbox Security Breach
**Impact:** Critical (destroys trust)
**Mitigation:**
- Use gVisor runtime
- Regular security audits
- Network segmentation
- Honeypot monitoring

### Risk 2: Analysis Accuracy Too Low
**Impact:** High (customers don't trust results)
**Mitigation:**
- Start with high-confidence only
- Provide confidence scores
- Allow manual review
- Continuous improvement based on feedback

### Risk 3: Infrastructure Costs Higher Than Expected
**Impact:** Medium (margin compression)
**Mitigation:**
- Aggressive auto-scaling down
- Cache analysis results (don't re-run same SHA)
- Tiered analysis depth (quick vs deep)

### Risk 4: Complexity Scares Customers
**Impact:** Medium (slow adoption)
**Mitigation:**
- Simple UI ("one-click analysis")
- Pre-configured defaults
- Clear documentation
- Video tutorials

---

## Next Steps (Today)

1. **Review this plan** - Adjust based on your priorities
2. **Choose MVP scope** - Decide what features for first 2 weeks
3. **Set up repo structure** - Create vexxy-enterprise service skeleton
4. **Define API contracts** - Spec out the integration points
5. **Build Phase 1 Week 1** - Get FastAPI + Celery + PostgreSQL running

**First Milestone:** Submit job via API → Queued → Returns "not implemented yet"
**Timeline:** 2 days

---

## Questions to Answer

Before starting implementation:

1. **Hosting:** Will you run this in your own K8s cluster or cloud managed?
2. **Storage:** S3, GCS, MinIO, or just PostgreSQL?
3. **Multi-tenancy:** One sandbox cluster for all customers or isolated?
4. **Billing:** Integrate with Stripe for usage-based billing?
5. **Monitoring:** Use existing monitoring or separate stack?

Let me know and we'll dive into implementation! 🚀
