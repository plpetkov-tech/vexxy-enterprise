# VEXxy Enterprise - Premium Features

This repository contains the **premium/enterprise features** for VEXxy, separate from the open-source core.

**Status:** Planning & Early Development
**Target Launch:** Q1 2026

---

## What's Here

### Premium VEX Generation Service (Ultimate Tier)

**The Competitive Moat:** Automated reachability-based VEX generation through runtime analysis.

**Value Proposition:** "The only platform that proves vulnerabilities are unreachable through runtime evidence"

**How it works:**
1. Customer submits container image for analysis
2. Image runs in isolated sandbox with eBPF profiling
3. Automated testing and fuzzing exercises code paths
4. Reachability analysis determines which CVEs are actually exploitable
5. Automated VEX documents generated with cryptographic evidence

**Pricing:**
- **Ultimate Tier:** $75K-150K/year (50-200 analyses/month included)
- **Ad-hoc:** $500-1000 per analysis

---

## Repository Structure

```
vexxy-enterprise/
├── README.md                           # This file
├── PREMIUM_VEX_INTEGRATION_PLAN.md     # Complete architecture & roadmap
├── QUICKSTART.md                        # Week 1 implementation guide
│
├── dope_workflows/                      # Reference GitHub Actions workflows
│   ├── vex-analysis.yml                # Full VEX generation pipeline
│   └── vex-integration.yml             # Production VEX integration
│
├── future/                              # Strategic planning docs
│   ├── README.md                       # Doc index
│   ├── ROADMAP_STRATEGY.md             # 24-month strategic plan
│   ├── EXECUTIVE_SUMMARY.md            # Quick overview
│   ├── PRICING.md                      # Customer-facing pricing
│   ├── POSITIONING_MESSAGING.md        # Marketing bible
│   ├── PITCH_DECK.md                   # Investor presentation
│   ├── SALES_PLAYBOOK.md               # Sales training
│   └── COMPETITIVE_BATTLE_CARDS.md     # Competitive intel
│
└── premium-service/                    # Premium VEX service (to be built)
    ├── api/                            # FastAPI service
    ├── workers/                        # Celery workers
    ├── models/                         # Database models
    ├── services/                       # Business logic
    │   ├── sandbox.py                 # K8s sandbox manager
    │   ├── profiler.py                # eBPF profiling
    │   ├── fuzzer.py                  # Security fuzzing
    │   ├── reachability.py            # Reachability analysis
    │   └── vex_generator.py           # VEX document generation
    ├── tests/                          # Test suite
    └── k8s/                            # Kubernetes manifests
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 14+
- Redis 7+
- Kubernetes cluster (for sandbox)
- Docker

### Week 1 Goal: Working Sandbox

Follow the **[QUICKSTART.md](QUICKSTART.md)** guide to get the basic service running in 1 week.

**What you'll have:**
- FastAPI service accepting analysis requests
- Celery workers processing jobs asynchronously
- Kubernetes jobs for isolated sandbox execution
- Basic log collection and status tracking

---

## Architecture

```
┌─────────────────┐
│  VEXxy Core     │  (Open Source - Separate Repo)
│  Backend + UI   │
└────────┬────────┘
         │ API calls
         ▼
┌─────────────────────────────────────────┐
│  Premium VEX Generation Service         │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │   Analysis Orchestrator         │   │
│  │   (FastAPI + Celery)            │   │
│  └─────────────────────────────────┘   │
│              │                          │
│              ▼                          │
│  ┌─────────────────────────────────┐   │
│  │   Sandbox Manager (K8s Jobs)    │   │
│  │   • gVisor isolation            │   │
│  │   • Resource limits             │   │
│  │   • Network policies            │   │
│  └─────────────────────────────────┘   │
│              │                          │
│       ┌──────┴──────┐                  │
│       ▼             ▼                   │
│  ┌────────┐   ┌──────────┐             │
│  │ Tracee │   │ OWASP ZAP │             │
│  │ (eBPF) │   │ (Fuzzer) │             │
│  └────────┘   └──────────┘             │
│       │             │                   │
│       └──────┬──────┘                  │
│              ▼                          │
│  ┌─────────────────────────────────┐   │
│  │  Reachability Analyzer          │   │
│  │  CVE → Code → Executed?         │   │
│  └─────────────────────────────────┘   │
│              │                          │
│              ▼                          │
│  ┌─────────────────────────────────┐   │
│  │  VEX Document Generator         │   │
│  │  (OpenVEX with evidence)        │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

---

## Development Roadmap

### Phase 1: MVP Foundation (Weeks 1-2) ⏳ IN PROGRESS
- [ ] FastAPI service skeleton
- [ ] Celery workers
- [ ] PostgreSQL schema
- [ ] Basic K8s sandbox execution
- [ ] Job status tracking

### Phase 2: Runtime Analysis (Weeks 3-4)
- [ ] Tracee integration (eBPF profiling)
- [ ] Execution profile collection
- [ ] Basic reachability algorithm
- [ ] Evidence collection

### Phase 3: VEX Generation (Weeks 5-6)
- [ ] OpenVEX document generation
- [ ] Confidence scoring
- [ ] Callback to vexxy backend
- [ ] UI integration
- [ ] Quota enforcement

### Phase 4: Production Hardening (Weeks 7-8)
- [ ] Security audit
- [ ] gVisor isolation
- [ ] Monitoring and alerting
- [ ] Error handling and retries
- [ ] Performance optimization

### Phase 5: Advanced Features (Weeks 9-12)
- [ ] OWASP ZAP fuzzing
- [ ] Code coverage analysis
- [ ] User-provided test scripts
- [ ] Multi-language support
- [ ] Scheduled re-analysis

---

## Key Documents

### For Implementation
- **[PREMIUM_VEX_INTEGRATION_PLAN.md](PREMIUM_VEX_INTEGRATION_PLAN.md)** - Complete technical architecture and development plan
- **[QUICKSTART.md](QUICKSTART.md)** - Get started in Week 1

### For Strategy
- **[future/ROADMAP_STRATEGY.md](future/ROADMAP_STRATEGY.md)** - 24-month strategic plan with market analysis
- **[future/EXECUTIVE_SUMMARY.md](future/EXECUTIVE_SUMMARY.md)** - Concise overview for external sharing

### For Sales & Marketing
- **[future/PRICING.md](future/PRICING.md)** - Customer-facing pricing page
- **[future/POSITIONING_MESSAGING.md](future/POSITIONING_MESSAGING.md)** - All marketing messaging
- **[future/SALES_PLAYBOOK.md](future/SALES_PLAYBOOK.md)** - Sales training and scripts

### Reference
- **[dope_workflows/vex-analysis.yml](dope_workflows/vex-analysis.yml)** - Production VEX workflow (GitHub Actions)

---

## Integration with VEXxy Core

This service is designed to integrate with the main VEXxy backend:

**API Flow:**
1. User requests analysis via VEXxy UI
2. VEXxy backend validates tier & quota
3. POST to premium service `/api/v1/analysis/submit`
4. Premium service queues job and processes async
5. Webhook callback to VEXxy backend with results
6. VEX documents stored in main VEXxy database

**Authentication:**
- Premium service validates requests via JWT from VEXxy backend
- Organization tier checked against license

**Quota Management:**
- Tracked in main VEXxy database
- Premium service enforces limits
- Overage billing calculated monthly

---

## Technology Stack

| Component | Technology | Why |
|-----------|------------|-----|
| API Service | FastAPI | Async, type-safe, fast development |
| Job Queue | Celery + Redis | Proven, scalable, you know it |
| Database | PostgreSQL | Main vexxy database |
| Sandbox | Kubernetes Jobs | Isolation, resource control |
| Profiling | Tracee (eBPF) | Runtime code execution tracking |
| Fuzzing | OWASP ZAP | Web app security testing |
| Storage | MinIO / S3 | Evidence and logs |
| Monitoring | Prometheus + Grafana | Observability |

---

## Security Considerations

**Sandbox Isolation:**
- Dedicated namespace (`vexxy-sandbox`)
- gVisor runtime for extra isolation
- Network policies (no internet by default)
- Resource quotas (prevent DoS)
- Timeout enforcement (max 15 min)

**Authentication:**
- JWT validation from VEXxy backend
- API key rotation
- Tier verification

**Data Protection:**
- Customer images never stored permanently
- Analysis results encrypted at rest
- Evidence files have TTL (90 days)
- Audit logs for compliance

---

## Cost Analysis

**Per-Analysis Costs:**
- Compute: ~$0.50 (10 min at $0.05/min on GCP)
- Storage: ~$0.02 (500MB evidence)
- **Total: ~$0.52 per analysis**

**Pricing:**
- Charge: $500-1000 per ad-hoc analysis
- **Margin: 99.9%** 💰

**Monthly Plan (Ultimate Tier):**
- Revenue: $100K/year = $8.3K/month
- Includes: 100 analyses/month
- Cost: ~$802/month (compute + infra)
- **Margin: 90%**

---

## Success Metrics

**Technical:**
- Analysis success rate: >95%
- Average analysis time: <10 minutes
- Sandbox security: Zero escapes
- VEX confidence: >85% average

**Business:**
- Month 3: 1 design partner
- Month 6: 3 paying customers ($225K ARR)
- Month 12: 10 customers ($750K ARR)

---

## Contributing

This is a **private repository** for VEXxy enterprise features.

**Team:**
- Plamen - Founder, primary developer

**Getting Started:**
1. Read `QUICKSTART.md`
2. Set up dev environment
3. Run tests: `pytest tests/ -v`
4. Submit PRs with clear descriptions

---

## License

**Proprietary** - VEXxy Enterprise Edition

The premium features in this repository are closed-source and licensed commercially.

For the open-source core, see: https://github.com/plpetkov-tech/vexxy (when public)

---

## Contact

**Questions?** Contact Plamen
**Issues?** Open GitHub issue in this repo
**Sales?** [Your sales email]

---

## Timeline

- **Now:** Planning & architecture
- **Nov 2025:** Week 1-2 MVP
- **Dec 2025:** Runtime analysis working
- **Jan 2026:** VEX generation complete
- **Feb 2026:** First design partner
- **Mar 2026:** Production-ready
- **Apr 2026:** General availability

---

**Let's build the future of VEX! 🚀**
