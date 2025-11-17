# VEXxy Enterprise - Quick Reference Guide

**Last Updated:** November 17, 2025

---

## At a Glance

**Architecture:** FastAPI (Python) + Celery workers + PostgreSQL + Kubernetes  
**Status:** MVP complete, billing implementation: 0%  
**Ready for billing:** YES - schema prepared, integration points identified

---

## API Framework

**FastAPI 0.104.1** on Uvicorn  
Base path: `/api/v1`

Core endpoints (all need authentication):
```
POST   /api/v1/analysis/submit
GET    /api/v1/analysis/{job_id}/status
GET    /api/v1/analysis/{job_id}/results
DELETE /api/v1/analysis/{job_id}
GET    /api/v1/analysis
GET    /api/v1/vex/{vex_id}
GET    /health
```

---

## Database Models

**Key Tables:**

1. **premium_analysis_jobs**
   - Main analysis tracking table
   - Has `organization_id` column (not yet linked to organizations table)
   - Has `billed_at` and `cost_credits` fields (ready for billing)

2. **analysis_evidence**
   - Evidence storage (execution traces, fuzzing results, VEX documents)

**Missing tables:**
- `organizations`
- `users`
- `subscriptions`
- `billing_events`
- `stripe_customers`

---

## Authentication Status

**Current:** Completely missing (dummy hardcoded organization_id)

```python
# api/main.py - Line 319
organization_id = "00000000-0000-0000-0000-000000000000"  # DUMMY
```

**TODO:** Implement JWT middleware + user/org models

---

## Task Processing

**Celery workers** process analysis jobs through 8 phases:

1. Kubescape check (5%)
2. Workload deployment (15%)
3. Readiness waiting (25%)
4. Kubernetes Service creation (30%)
5. OWASP ZAP security scan (32%)
6. Kubescape analysis waiting (50%)
7. VEX/SBOM extraction (80%)
8. Cleanup (100%)

**Billing integration point:** After phase 8 - calculate and store cost

---

## Services Architecture

| Service | Purpose | Lines |
|---------|---------|-------|
| KubescapeService | Runtime VEX generation via Kubescape | 450 |
| EvidenceStorage | Evidence persistence | 240 |
| ReachabilityAnalyzer | CVE reachability analysis | 400 |
| ZAPService | OWASP ZAP security fuzzing | 600 |
| SandboxManager | K8s sandbox lifecycle | 320 |
| ProfilerService | eBPF runtime profiling | 320 |
| SBOMService | SBOM handling | 240 |

---

## Environment Configuration

**Location:** `config/settings.py`

Key settings:
```python
api_host: str = "0.0.0.0"
api_port: int = 8001
database_url: str = "postgresql://..."
redis_url: str = "redis://..."
k8s_sandbox_namespace: str = "vexxy-sandbox"
jwt_secret_key: str = "change-me-in-production"  # UNUSED
```

**To add for billing:**
```python
stripe_secret_key: str
stripe_publishable_key: str
stripe_webhook_secret: str
```

---

## Dependencies to Add

```
stripe==5.18.0          # Stripe Python SDK
pyjwt==2.8.1            # JWT token handling
```

---

## Critical Integration Points

### Point 1: Authentication Middleware
- **File to create:** `middleware/authentication.py`
- **Function:** Extract JWT token, validate, load org context
- **Add to:** All endpoints in `api/main.py`

### Point 2: Quota Checking
- **File to create:** `utils/quota.py`
- **Function:** Check credits, analyses/month limit before submission
- **Add to:** `api/main.py:submit_analysis()` line 320

### Point 3: Cost Calculation
- **File to modify:** `workers/tasks.py`
- **Function:** Calculate job cost after phase 8, update `job.cost_credits`
- **When:** After cleanup, before task completion

### Point 4: Webhook Processing
- **File to create:** `api/webhooks.py`
- **Function:** Handle Stripe events (subscription, invoice, payment)
- **Endpoint:** `POST /api/v1/webhooks/stripe`

### Point 5: Billing API
- **File to create:** `api/billing.py`
- **Endpoints:**
  - `GET /api/v1/billing/{org_id}/subscription`
  - `GET /api/v1/billing/{org_id}/credits`
  - `GET /api/v1/billing/{org_id}/usage`
  - `GET /api/v1/billing/{org_id}/invoices`

---

## Files to Create for Billing (7 New)

1. `models/billing.py` - Organization, User, Subscription, BillingEvent models
2. `middleware/authentication.py` - JWT validation middleware
3. `services/billing.py` - StripeService, BillingService, QuotaService
4. `api/billing.py` - Billing API endpoints
5. `api/webhooks.py` - Stripe webhook handler
6. `utils/quota.py` - Quota enforcement utilities
7. `migrations/XXX_add_billing_tables.sql` - Database migrations

---

## Files to Modify for Billing (5 Existing)

1. `api/main.py` - Add auth dependency, quota checking
2. `workers/tasks.py` - Cost calculation, billing events
3. `config/settings.py` - Stripe configuration
4. `requirements.txt` - Add stripe, pyjwt
5. `models/analysis.py` - Link to Organization table

---

## Error Handling (Ready to Use)

All custom exceptions in `exceptions.py`:

- `QuotaExceededError` (429) - Perfect for quota violations
- `ValidationError` (400) - Input validation
- `InvalidJobStateError` (409) - State conflicts
- `InternalServiceError` (500) - Generic errors
- `DatabaseError` (500) - DB failures

---

## Code Statistics

- **Total Python files:** 30
- **Total lines:** ~3,500
- **Largest files:** api/main.py (650), services/kubescape.py (450), workers/tasks.py (400)
- **Test coverage:** 0% (no tests yet)

---

## Deployment Architecture

```
┌─────────────────────────┐
│   FastAPI Service       │
│   Port 8001             │
└─────────────────────────┘
          │
┌─────────┴──────────────────────────┐
│                                    │
v                                    v
Redis (Queue)              PostgreSQL (Jobs DB)
Port 6379                  Port 5432
│
v
Celery Worker(s)
│
v
Kubernetes Cluster (vexxy-sandbox namespace)
```

---

## Quick Start for Billing Integration

**Week 1: Auth**
1. Create Organization, User models
2. Create JWT middleware
3. Add auth to all endpoints

**Week 2: Subscriptions**
1. Create Subscription, Tier models
2. Set up Stripe customer creation
3. Create subscription endpoints

**Week 2-3: Billing**
1. Create BillingEvent model
2. Add cost calculation in workers
3. Implement credit deduction

**Week 3: Quotas**
1. Create QuotaService
2. Add pre-submission checks
3. Add QuotaExceededError handling

**Week 4: Webhooks & API**
1. Implement Stripe webhooks
2. Create billing API endpoints
3. Test with Stripe sandbox

---

## Useful Absolute Paths

```
/home/user/vexxy-enterprise/premium-service/api/main.py
/home/user/vexxy-enterprise/premium-service/models/analysis.py
/home/user/vexxy-enterprise/premium-service/workers/tasks.py
/home/user/vexxy-enterprise/premium-service/services/
/home/user/vexxy-enterprise/premium-service/middleware/
/home/user/vexxy-enterprise/premium-service/config/settings.py
/home/user/vexxy-enterprise/premium-service/exceptions.py
```

---

## Key TODOs Currently in Code

```python
# api/main.py:317-322
# TODO: Authentication & authorization
# TODO: Quota check
# TODO: Set priority based on tier
# TODO: Cancel Celery task and cleanup sandbox

# config/settings.py:68-74
jwt_secret_key: str = "change-me-in-production"
jwt_algorithm: str = "HS256"
# (Both unused, awaiting auth implementation)
```

---

## Next Steps

1. Read `CODEBASE_ANALYSIS.md` for detailed breakdown
2. Review `CODEBASE_STRUCTURE.txt` for file organization
3. Start with authentication middleware (Week 1 work)
4. Use `QuotaExceededError` exception (already available)
5. Leverage existing error handling and logging infrastructure

---

**Full documentation:** See `CODEBASE_ANALYSIS.md` for complete details
**File map:** See `CODEBASE_STRUCTURE.txt` for directory tree
