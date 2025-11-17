# VEXxy Enterprise Billing API Integration Specification

**Version:** 1.0
**Last Updated:** 2025-11-17
**Status:** Implementation Complete

## Overview

This document specifies the billing and subscription functionality exposed by the VEXxy Enterprise (Premium) service. The base VEXxy application (open-core) should integrate with this API to enable premium features based on user subscriptions and credit balance.

## Architecture

### Service Separation

- **Base VEXxy (Open-Core)**: Core VEX generation, SBOM management, vulnerability tracking
- **VEXxy Enterprise (Premium)**: Advanced runtime analysis, billing, subscriptions, quota management

### Integration Pattern

```
┌─────────────────────────────────────────────────────────────┐
│                      Base VEXxy Application                 │
│                      (Open-Core / Free Tier)                │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Feature Flag: premium_analysis_enabled              │  │
│  │                                                       │  │
│  │  IF enabled AND user has subscription:               │  │
│  │    → Call Premium API                                │  │
│  │  ELSE:                                               │  │
│  │    → Use basic/free features only                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                            │                                │
│                            │ HTTP/REST                      │
│                            ▼                                │
└────────────────────────────┼────────────────────────────────┘
                             │
                             │
┌────────────────────────────┼────────────────────────────────┐
│                            ▼                                │
│              VEXxy Enterprise Premium Service               │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ Billing API  │  │ Analysis API │  │  Stripe      │    │
│  │              │  │              │  │  Webhooks    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  PostgreSQL Database                                 │  │
│  │  - Organizations, Users, Subscriptions              │  │
│  │  - Billing Events, API Keys                         │  │
│  │  - Analysis Jobs, Evidence                          │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                             │
                             │
                             ▼
                    ┌─────────────────┐
                    │  Stripe API     │
                    │  (Payments)     │
                    └─────────────────┘
```

---

## Authentication

### JWT Token-Based Authentication

All premium API endpoints (except webhooks and public endpoints) require JWT authentication.

#### Token Format

```http
Authorization: Bearer <jwt_token>
```

#### Token Payload

```json
{
  "sub": "user-uuid",
  "org_id": "organization-uuid",
  "email": "user@example.com",
  "is_admin": false,
  "exp": 1732838400,
  "iat": 1732752000
}
```

#### Token Generation

The base VEXxy application should implement JWT token generation when users authenticate:

```python
from jwt import encode
from datetime import datetime, timedelta

def create_premium_token(user):
    payload = {
        "sub": str(user.id),
        "org_id": str(user.organization_id),
        "email": user.email,
        "is_admin": user.is_organization_admin,
        "exp": datetime.utcnow() + timedelta(hours=24),
        "iat": datetime.utcnow()
    }

    token = encode(
        payload,
        JWT_SECRET_KEY,  # Must match premium service config
        algorithm="HS256"
    )

    return token
```

#### Configuration

Both services must share the same JWT secret:

**Base VEXxy `.env`:**
```bash
JWT_SECRET_KEY=your-secret-key-here
PREMIUM_API_URL=http://premium-service:8001
```

**Premium Service `.env`:**
```bash
JWT_SECRET_KEY=your-secret-key-here  # MUST MATCH
```

---

## API Endpoints

### Base URL

```
http://premium-service:8001
```

---

## 1. Billing & Subscription Endpoints

### 1.1 Get Current Subscription

**Endpoint:** `GET /api/v1/billing/subscription`

**Authentication:** Required (JWT Bearer token)

**Description:** Get the authenticated user's organization subscription details.

**Response:**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "organization_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "tier": "professional",
  "status": "active",
  "monthly_analysis_limit": 500,
  "monthly_credit_limit": 5000,
  "current_period_analyses": 47,
  "current_period_credits_used": 523,
  "current_period_start": "2025-11-01T00:00:00Z",
  "current_period_end": "2025-12-01T00:00:00Z",
  "trial_end": null,
  "cancel_at_period_end": false,
  "created_at": "2025-10-01T14:30:00Z"
}
```

**Integration Point:**

```python
# In base VEXxy - check if user has active subscription
def has_premium_access(user_token):
    response = requests.get(
        f"{PREMIUM_API_URL}/api/v1/billing/subscription",
        headers={"Authorization": f"Bearer {user_token}"}
    )

    if response.status_code == 200:
        subscription = response.json()
        return subscription["status"] in ["active", "trialing"]

    return False
```

---

### 1.2 Get Credit Balance

**Endpoint:** `GET /api/v1/billing/credits`

**Authentication:** Required

**Response:**

```json
{
  "organization_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "credit_balance": 4477,
  "organization_name": "Acme Corp"
}
```

**Integration Point:**

```python
# Show credit balance in UI
def get_credit_balance(user_token):
    response = requests.get(
        f"{PREMIUM_API_URL}/api/v1/billing/credits",
        headers={"Authorization": f"Bearer {user_token}"}
    )

    return response.json()["credit_balance"]
```

---

### 1.3 Get Usage Statistics

**Endpoint:** `GET /api/v1/billing/usage`

**Authentication:** Required

**Response:**

```json
{
  "organization_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "current_period_analyses": 47,
  "current_period_credits_used": 523,
  "monthly_analysis_limit": 500,
  "monthly_credit_limit": 5000,
  "current_period_start": "2025-11-01T00:00:00Z",
  "current_period_end": "2025-12-01T00:00:00Z",
  "utilization_percent": 10.46
}
```

**Integration Point:**

```python
# Display usage statistics in dashboard
def get_usage_stats(user_token):
    response = requests.get(
        f"{PREMIUM_API_URL}/api/v1/billing/usage",
        headers={"Authorization": f"Bearer {user_token}"}
    )

    return response.json()
```

---

### 1.4 Get Billing Event History

**Endpoint:** `GET /api/v1/billing/events`

**Authentication:** Required

**Query Parameters:**
- `limit` (int, default: 50): Number of events to return
- `offset` (int, default: 0): Pagination offset

**Response:**

```json
[
  {
    "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "organization_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "event_type": "analysis_completed",
    "description": "Analysis job abc-123 completed with cost 15 credits",
    "analysis_job_id": "abc-123...",
    "credits_amount": -15,
    "balance_after": 4477,
    "created_at": "2025-11-17T10:30:00Z"
  },
  {
    "id": "8d0e7680-8536-41ef-955c-f18gd2g01bf8",
    "organization_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "event_type": "credit_purchased",
    "description": "Purchased 1000 credits for $100.00",
    "analysis_job_id": null,
    "credits_amount": 1000,
    "balance_after": 4492,
    "created_at": "2025-11-16T08:15:00Z"
  }
]
```

---

### 1.5 Get Available Tiers

**Endpoint:** `GET /api/v1/billing/tiers`

**Authentication:** Not required (public)

**Response:**

```json
[
  {
    "tier": "free",
    "monthly_analysis_limit": 10,
    "monthly_credit_limit": 100,
    "priority": 0,
    "features": ["basic_analysis", "vex_generation"]
  },
  {
    "tier": "starter",
    "monthly_analysis_limit": 100,
    "monthly_credit_limit": 1000,
    "priority": 1,
    "features": ["basic_analysis", "vex_generation", "reachability_analysis"]
  },
  {
    "tier": "professional",
    "monthly_analysis_limit": 500,
    "monthly_credit_limit": 5000,
    "priority": 2,
    "features": [
      "basic_analysis",
      "vex_generation",
      "reachability_analysis",
      "security_fuzzing",
      "priority_support"
    ]
  },
  {
    "tier": "enterprise",
    "monthly_analysis_limit": null,
    "monthly_credit_limit": null,
    "priority": 3,
    "features": [
      "basic_analysis",
      "vex_generation",
      "reachability_analysis",
      "security_fuzzing",
      "priority_support",
      "dedicated_support",
      "custom_integrations"
    ]
  }
]
```

**Integration Point:**

```python
# Display pricing tiers in UI
def get_pricing_tiers():
    response = requests.get(f"{PREMIUM_API_URL}/api/v1/billing/tiers")
    return response.json()
```

---

## 2. Premium Analysis Endpoints

### 2.1 Submit Premium Analysis

**Endpoint:** `POST /api/v1/analysis/submit`

**Authentication:** Required

**Request Body:**

```json
{
  "image_ref": "nginx:1.25",
  "image_digest": "sha256:abc123...",
  "sbom_id": "550e8400-e29b-41d4-a716-446655440000",
  "config": {
    "test_script": "curl http://localhost:80",
    "test_timeout": 300,
    "enable_fuzzing": true,
    "enable_profiling": true,
    "enable_code_coverage": false,
    "ports": [80, 443],
    "environment": {
      "ENV_VAR": "value"
    }
  }
}
```

**Response:**

```json
{
  "job_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "status": "queued",
  "image_ref": "nginx:1.25",
  "image_digest": "sha256:abc123...",
  "estimated_duration_minutes": 10,
  "created_at": "2025-11-17T10:00:00Z"
}
```

**Cost Calculation:**

The analysis cost is calculated based on:
- **Base cost**: 10 credits
- **Security fuzzing** (if enabled): +5 credits
- **Profiling** (if enabled): +3 credits
- **Code coverage** (if enabled): +7 credits
- **Duration**: +1 credit per 5 minutes

**Integration Point:**

```python
# Submit analysis from base VEXxy
def submit_premium_analysis(user_token, image_ref, image_digest, sbom_id):
    response = requests.post(
        f"{PREMIUM_API_URL}/api/v1/analysis/submit",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "image_ref": image_ref,
            "image_digest": image_digest,
            "sbom_id": sbom_id,
            "config": {
                "enable_fuzzing": True,
                "enable_profiling": True,
                "ports": [80]
            }
        }
    )

    if response.status_code == 201:
        return response.json()["job_id"]
    elif response.status_code == 429:
        raise QuotaExceededError("Monthly quota exceeded")
    else:
        raise Exception(f"Analysis submission failed: {response.text}")
```

---

### 2.2 Get Analysis Status

**Endpoint:** `GET /api/v1/analysis/{job_id}/status`

**Authentication:** Required

**Response:**

```json
{
  "job_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "status": "running",
  "progress_percent": 45,
  "current_phase": "Running OWASP ZAP security scan",
  "created_at": "2025-11-17T10:00:00Z",
  "started_at": "2025-11-17T10:00:15Z",
  "estimated_completion": "2025-11-17T10:10:00Z"
}
```

**Status Values:**
- `queued`: Waiting to start
- `running`: Analysis in progress
- `analyzing`: Post-processing results
- `complete`: Analysis finished successfully
- `failed`: Analysis failed with errors
- `cancelled`: Analysis was cancelled by user

---

### 2.3 Get Analysis Results

**Endpoint:** `GET /api/v1/analysis/{job_id}/results`

**Authentication:** Required

**Response:**

```json
{
  "job_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "status": "complete",
  "image_ref": "nginx:1.25",
  "image_digest": "sha256:abc123...",
  "vex_document": {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://vexxy.example.com/vex/...",
    "author": "VEXxy Premium Analysis",
    "statements": [...]
  },
  "execution_profile": {...},
  "reachability_results": {...},
  "security_findings": {
    "total_alerts": 3,
    "high_risk": 0,
    "medium_risk": 2,
    "low_risk": 1
  },
  "cost_credits": 18,
  "completed_at": "2025-11-17T10:09:47Z"
}
```

**Integration Point:**

```python
# Poll for results and store VEX document
def get_analysis_results(user_token, job_id):
    response = requests.get(
        f"{PREMIUM_API_URL}/api/v1/analysis/{job_id}/results",
        headers={"Authorization": f"Bearer {user_token}"}
    )

    if response.status_code == 200:
        results = response.json()

        if results["status"] == "complete":
            # Store VEX document in base VEXxy database
            store_vex_document(results["vex_document"])
            return results
        else:
            # Still processing
            return None
    else:
        raise Exception(f"Failed to get results: {response.text}")
```

---

## 3. Error Responses

### Error Format

All errors follow a consistent format:

```json
{
  "error": "QUOTA_EXCEEDED",
  "message": "Monthly analysis limit reached (500/500)",
  "details": {
    "quota_type": "monthly_analyses",
    "limit": 500,
    "current": 500
  },
  "timestamp": "2025-11-17T10:00:00Z"
}
```

### Common Error Codes

| Status Code | Error Code | Description |
|-------------|------------|-------------|
| 400 | `VALIDATION_ERROR` | Invalid request data |
| 401 | `UNAUTHORIZED` | Missing or invalid authentication |
| 403 | `FORBIDDEN` | Insufficient permissions |
| 404 | `RESOURCE_NOT_FOUND` | Resource does not exist |
| 409 | `RESOURCE_CONFLICT` | Conflicting state |
| 429 | `QUOTA_EXCEEDED` | Quota/rate limit exceeded |
| 500 | `INTERNAL_ERROR` | Internal server error |
| 502 | `EXTERNAL_SERVICE_ERROR` | Dependency failure |
| 503 | `SERVICE_UNAVAILABLE` | Service temporarily unavailable |

---

## 4. Feature Flag Integration

### Recommended Feature Flags

Configure these in the base VEXxy application:

```python
# config/feature_flags.py
FEATURE_FLAGS = {
    "premium_analysis_enabled": os.getenv("PREMIUM_ANALYSIS_ENABLED", "false").lower() == "true",
    "billing_enabled": os.getenv("BILLING_ENABLED", "false").lower() == "true",
    "show_upgrade_prompts": os.getenv("SHOW_UPGRADE_PROMPTS", "true").lower() == "true",
}
```

### Implementation Pattern

```python
# In base VEXxy application
from config.feature_flags import FEATURE_FLAGS

def analyze_image(user, image_ref, image_digest):
    # Always generate SBOM (free tier feature)
    sbom = generate_sbom(image_ref)

    # Check if premium analysis is enabled
    if FEATURE_FLAGS["premium_analysis_enabled"]:
        # Check if user has subscription
        if has_premium_subscription(user):
            # Submit to premium service
            token = create_premium_token(user)
            job_id = submit_premium_analysis(token, image_ref, image_digest, sbom.id)

            return {
                "type": "premium",
                "job_id": job_id,
                "status": "queued"
            }

    # Fall back to basic analysis (free tier)
    basic_vex = generate_basic_vex(sbom)

    return {
        "type": "basic",
        "vex_document": basic_vex
    }
```

---

## 5. Subscription Management Integration

### User Flow for Upgrading

1. **User clicks "Upgrade" in base VEXxy UI**
2. **Base VEXxy redirects to billing page** (can be hosted in premium service or base app)
3. **User selects tier and enters payment info**
4. **Payment processed via Stripe**
5. **Webhook updates subscription in premium service**
6. **User redirected back to base VEXxy**
7. **Base VEXxy checks subscription status** and enables premium features

### Stripe Integration

The premium service handles all Stripe integration. Base VEXxy just needs to:

1. Link to the premium service's billing portal
2. Check subscription status via API
3. Enforce feature access based on subscription tier

**Example:**

```html
<!-- In base VEXxy UI -->
<div class="upgrade-banner">
  <p>Get advanced runtime analysis with Premium!</p>
  <a href="{{ PREMIUM_API_URL }}/billing/subscribe">
    Upgrade Now
  </a>
</div>
```

---

## 6. Webhook Configuration (Stripe)

The premium service exposes a webhook endpoint for Stripe events:

**Endpoint:** `POST /api/v1/webhooks/stripe`

**Authentication:** Stripe signature verification

**Events Handled:**
- `payment_intent.succeeded`
- `payment_intent.payment_failed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.payment_succeeded`
- `invoice.payment_failed`

**Stripe Dashboard Configuration:**

```
Webhook URL: https://your-domain.com/api/v1/webhooks/stripe
Events: Select all subscription and payment events
```

---

## 7. Environment Variables

### Required Configuration

**Base VEXxy `.env`:**

```bash
# Premium service integration
PREMIUM_ANALYSIS_ENABLED=true
PREMIUM_API_URL=http://premium-service:8001
JWT_SECRET_KEY=your-shared-secret-key

# Feature flags
BILLING_ENABLED=true
SHOW_UPGRADE_PROMPTS=true
```

**Premium Service `.env`:**

```bash
# JWT Configuration (MUST MATCH BASE APP)
JWT_SECRET_KEY=your-shared-secret-key
JWT_ALGORITHM=HS256

# Stripe Configuration
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/vexxy_premium

# Redis (for Celery)
REDIS_URL=redis://localhost:6379/0

# Kubernetes
K8S_SANDBOX_NAMESPACE=vexxy-sandbox
K8S_IN_CLUSTER=true
```

---

## 8. Database Schema (Premium Service)

The premium service manages these tables:

### Organizations

```sql
CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    stripe_customer_id VARCHAR(255) UNIQUE,
    credit_balance INTEGER DEFAULT 0,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### Users

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    hashed_password VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP
);
```

### Subscriptions

```sql
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) UNIQUE,
    tier VARCHAR(50),  -- free, starter, professional, enterprise
    status VARCHAR(50),  -- active, trialing, past_due, canceled
    monthly_analysis_limit INTEGER,
    monthly_credit_limit INTEGER,
    current_period_analyses INTEGER DEFAULT 0,
    current_period_credits_used INTEGER DEFAULT 0,
    current_period_start TIMESTAMP,
    current_period_end TIMESTAMP,
    stripe_subscription_id VARCHAR(255) UNIQUE,
    created_at TIMESTAMP
);
```

### Billing Events

```sql
CREATE TABLE billing_events (
    id UUID PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id),
    event_type VARCHAR(50),  -- analysis_completed, credit_purchased, etc.
    description TEXT,
    analysis_job_id UUID,
    credits_amount INTEGER,
    balance_after INTEGER,
    stripe_event_id VARCHAR(255) UNIQUE,
    created_at TIMESTAMP
);
```

---

## 9. Testing & Development

### Testing Premium Integration

1. **Create test organization and user**:

```bash
curl -X POST http://localhost:8001/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpass123",
    "name": "Test User",
    "organization_name": "Test Org"
  }'
```

2. **Get JWT token**:

```bash
curl -X POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpass123"
  }'
```

3. **Check subscription**:

```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8001/api/v1/billing/subscription
```

4. **Submit test analysis**:

```bash
curl -X POST http://localhost:8001/api/v1/analysis/submit \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "image_ref": "nginx:latest",
    "image_digest": "sha256:abc123...",
    "config": {
      "enable_fuzzing": true
    }
  }'
```

### Stripe Test Mode

Use Stripe test keys for development:

```bash
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
```

Test cards:
- Success: `4242 4242 4242 4242`
- Decline: `4000 0000 0000 0002`

---

## 10. Deployment Considerations

### Service Communication

- **Internal**: Services communicate via internal Kubernetes DNS
- **External**: Users access via ingress/load balancer

### Recommended Architecture

```yaml
# Kubernetes services
apiVersion: v1
kind: Service
metadata:
  name: vexxy-base
spec:
  selector:
    app: vexxy-base
  ports:
    - port: 8000
      targetPort: 8000
---
apiVersion: v1
kind: Service
metadata:
  name: vexxy-premium
spec:
  selector:
    app: vexxy-premium
  ports:
    - port: 8001
      targetPort: 8001
```

### Environment-specific URLs

```bash
# Development
PREMIUM_API_URL=http://localhost:8001

# Staging
PREMIUM_API_URL=http://vexxy-premium.staging.svc.cluster.local:8001

# Production
PREMIUM_API_URL=http://vexxy-premium.production.svc.cluster.local:8001
```

---

## 11. Monitoring & Observability

### Key Metrics to Track

**In Base VEXxy:**
- Premium API call latency
- Premium API error rate
- Subscription check failures
- Feature flag usage

**In Premium Service:**
- Analysis job queue depth
- Credit consumption rate
- Quota exceeded frequency
- Webhook processing latency

### Recommended Logging

```python
# Log premium API calls
logger.info("Premium analysis submitted", extra={
    "user_id": user.id,
    "organization_id": user.organization_id,
    "image_ref": image_ref,
    "job_id": job_id,
    "estimated_cost": 15
})
```

---

## 12. Security Considerations

### JWT Secret Management

- **NEVER** commit JWT secrets to version control
- Use Kubernetes secrets or secret management service
- Rotate secrets periodically
- Use different secrets for dev/staging/prod

### API Security

- Always use HTTPS in production
- Rate limit API endpoints
- Validate all input data
- Log authentication failures
- Monitor for suspicious activity

### PCI Compliance

- **DO NOT** store credit card data
- All payment processing handled by Stripe
- Only store Stripe customer/subscription IDs

---

## Summary

This specification provides everything needed to integrate the base VEXxy application with the VEXxy Enterprise Premium service:

1. **Authentication**: JWT token-based, shared secret
2. **Billing API**: Subscription status, credit balance, usage stats
3. **Analysis API**: Submit jobs, check status, retrieve results
4. **Feature Flags**: Enable/disable premium features
5. **Error Handling**: Consistent error responses
6. **Webhooks**: Stripe payment events

The integration is designed to be:
- **Simple**: REST API with JWT auth
- **Flexible**: Feature flags control behavior
- **Reliable**: Graceful fallbacks to free tier
- **Secure**: Token-based auth, HTTPS, input validation

For questions or issues, please refer to the API documentation at:
```
http://premium-service:8001/docs
```
