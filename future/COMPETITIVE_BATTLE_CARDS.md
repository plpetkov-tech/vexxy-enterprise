# VEXxy: Competitive Battle Cards

**Version:** 1.0
**Date:** November 2025
**For:** Sales Team

---

## How to Use These Battle Cards

**Before the call:**
- Review the specific competitor you're up against
- Understand their strengths (acknowledge them)
- Prepare to position VEXxy's advantages

**During the call:**
- Never trash the competitor ("Chainguard sucks")
- Acknowledge their strengths ("Chainguard is great for...")
- Differentiate on value, not features
- Focus on customer needs, not product specs

**Key Principle:** *"We're not better at everything. We're better at VEX management."*

---

## Battle Card: Chainguard

### Overview
- **What they do:** Provide hardened, minimal container images with built-in VEX
- **Target market:** Security-conscious enterprises, compliance-driven orgs
- **Pricing:** $50K-200K+/year
- **Strengths:** Strong brand, well-funded, reachability analysis for their images
- **Weaknesses:** Only works with Chainguard images (vendor lock-in), expensive

### When You're Competing

**Likely scenario:** Prospect is evaluating Chainguard images and asks, "Why would we need VEXxy if Chainguard provides VEX?"

**Your response:**

"Chainguard is excellent if you're using their images. But here's the reality: most organizations have a mix:
- Third-party images (databases, message queues, etc.)
- Legacy images they can't easily replace
- Custom applications built on standard base images
- Community images from Docker Hub or Quay

**Chainguard only provides VEX for Chainguard images.** What about the other 80% of your infrastructure?

VEXxy works with ANY image from ANY registry. You can:
- Use Chainguard images where it makes sense (high-risk apps)
- Use VEXxy to manage VEX for everything else
- Centralize VEX data from both in one platform

Plus, we're open source, so no vendor lock-in."

### Feature Comparison

| Feature | VEXxy | Chainguard |
|---------|:-----:|:----------:|
| Works with any image | ✅ | ❌ (Chainguard only) |
| Reachability VEX | ✅ | ✅ (Chainguard images) |
| Open source | ✅ | ❌ |
| Multi-scanner support | ✅ | ❌ (Grype only) |
| Price (starting) | $5K | $50K+ |
| Centralized VEX mgmt | ✅ | ❌ |

### Landmine Questions

**Questions to ask that highlight Chainguard's limitations:**

1. "What percentage of your images are Chainguard images vs. other sources?"
   - **Why:** Likely <20%, shows need for broader solution

2. "How do you manage VEX for images that aren't from Chainguard?"
   - **Why:** They don't have an answer, creates pain

3. "Are you willing to replace all your base images with Chainguard equivalents?"
   - **Why:** Expensive, time-consuming, risky

4. "What if you need to change base image vendors in the future?"
   - **Why:** Vendor lock-in concern

### Win/Loss Intel

**Why customers choose VEXxy over Chainguard:**
- ✅ Need VEX for all images, not just Chainguard
- ✅ Price (10x cheaper)
- ✅ Flexibility (not locked to one vendor)

**Why customers choose Chainguard over VEXxy:**
- They want turnkey hardened images (convenience)
- They have budget and want "white glove" service
- They perceive Chainguard as more mature/established

**How to reposition if you're losing:**
"We're not mutually exclusive. Use Chainguard for your most critical images, VEXxy for everything else. You'll get best of both worlds."

---

## Battle Card: Anchore (Grype/Syft)

### Overview
- **What they do:** Open-source vulnerability scanner (Grype) and SBOM generator (Syft), plus enterprise platform
- **Target market:** DevOps teams, security teams, enterprises
- **Pricing:** Free (OSS), $10K-100K+ (Enterprise)
- **Strengths:** Popular OSS tools (20K+ stars), good scanning, enterprise features
- **Weaknesses:** VEX is secondary feature, limited enrichment, no reachability

### When You're Competing

**Likely scenario:** Prospect says, "We already use Grype. Why do we need VEXxy?"

**Your response:**

"Grype is an excellent scanner, and we actually integrate with it! But here's the difference:

**Grype's job:** Find vulnerabilities
**VEXxy's job:** Manage VEX and prioritize vulnerabilities

Think of it like this:
- Grype tells you what vulnerabilities exist (the scanner)
- VEXxy tells you which ones matter and helps you document why others don't (the management layer)

Many customers use both: Grype scans their images, VEXxy ingests those results, enriches them with 20+ intelligence sources, detects false positives, and generates VEX statements.

**You're not replacing Grype—you're making it more useful.**"

### Feature Comparison

| Feature | VEXxy | Anchore (Grype) |
|---------|:-----:|:---------------:|
| Vulnerability scanning | Via integration | ✅ (Core feature) |
| VEX management | ✅ (Core feature) | Partial |
| Enrichment sources | 20+ | ~3 |
| False positive detection | ✅ | Basic |
| Reachability VEX | ✅ (Ultimate) | ❌ |
| Hierarchical VEX scoping | ✅ | ❌ |
| Multi-scanner support | ✅ | ❌ (Grype only) |
| Open source | ✅ | ✅ |
| Price (enterprise) | $5K-150K | $10K-100K |

### Landmine Questions

1. "How do you currently manage VEX statements at scale?"
   - **Why:** Anchore's VEX support is limited, they likely don't have good process

2. "How many intelligence sources does Anchore use to enrich vulnerabilities?"
   - **Why:** ~3 vs. our 20+, shows depth difference

3. "Can Anchore prove that a vulnerability's code path is never executed?"
   - **Why:** No reachability analysis, we can

4. "Do you use multiple scanners (Trivy, Grype, others)? How do you centralize results?"
   - **Why:** Anchore is single-scanner focused, we support all

### Win/Loss Intel

**Why customers choose VEXxy over Anchore:**
- ✅ Need deeper VEX capabilities (not just basic support)
- ✅ Want multi-scanner support (not locked to Grype)
- ✅ Need reachability analysis (Ultimate tier)
- ✅ Want more enrichment sources

**Why customers choose Anchore over VEXxy:**
- They want all-in-one (scanning + VEX in one product)
- They're already Anchore Enterprise customers
- They don't need deep VEX features

**How to reposition if you're losing:**
"We're actually complementary to Anchore. Keep using Grype for scanning—it's great. Use VEXxy for the VEX management layer. Best of both worlds."

---

## Battle Card: Dependency-Track

### Overview
- **What they do:** Open-source SBOM and vulnerability tracking platform (OWASP)
- **Target market:** SBOM-focused orgs, component risk analysis
- **Pricing:** Free (OSS)
- **Strengths:** Mature OWASP project, free, good SBOM management, active community
- **Weaknesses:** Not K8s-native, limited VEX, dated UI, not cloud-native

### When You're Competing

**Likely scenario:** Prospect says, "Dependency-Track is free and does SBOM. Why pay for VEXxy?"

**Your response:**

"Dependency-Track is a solid OWASP project, and for pure SBOM tracking it works well. But there are key differences for Kubernetes environments:

**1. Kubernetes-native design:**
- VEXxy understands clusters, namespaces, workloads, deployments
- Dependency-Track treats everything as generic components (not K8s-aware)

**2. VEX capabilities:**
- VEXxy has advanced VEX with hierarchical scoping (global → project → cluster → namespace → workload)
- Dependency-Track has basic VEX support

**3. Reachability analysis (Ultimate tier):**
- VEXxy proves vulnerability exploitability with runtime analysis
- Dependency-Track can't do this

**4. Modern UX:**
- VEXxy: React 19, modern design
- Dependency-Track: Java-based UI (more dated)

**5. Enrichment:**
- VEXxy: 20+ intelligence sources
- Dependency-Track: Fewer sources

If you're in a Kubernetes environment and need advanced VEX, VEXxy is purpose-built for that. If you just need basic SBOM tracking, Dependency-Track might be sufficient."

### Feature Comparison

| Feature | VEXxy | Dependency-Track |
|---------|:-----:|:----------------:|
| SBOM management | ✅ | ✅ |
| VEX management | ✅ (Advanced) | Basic |
| Kubernetes-native | ✅ | ❌ |
| Deployment tracking | ✅ | ❌ |
| Reachability VEX | ✅ (Ultimate) | ❌ |
| False positive detection | ✅ | Basic |
| Modern UI | ✅ | ❌ (dated) |
| Open source | ✅ | ✅ |
| Price | Free → $150K | Free |

### Landmine Questions

1. "Are you running Kubernetes? How does Dependency-Track handle deployment-aware vulnerability management?"
   - **Why:** It doesn't—not K8s-native

2. "How deep are Dependency-Track's VEX capabilities?"
   - **Why:** Basic, not advanced like ours

3. "Can you scope VEX statements at the namespace or workload level?"
   - **Why:** No hierarchical scoping

4. "Does your team like the Dependency-Track UI, or do they find it dated?"
   - **Why:** Common complaint, we can show modern alternative

### Win/Loss Intel

**Why customers choose VEXxy over Dependency-Track:**
- ✅ Running Kubernetes (need K8s-native features)
- ✅ Need advanced VEX (not just basic SBOM)
- ✅ Want modern UX
- ✅ Need reachability analysis

**Why customers choose Dependency-Track over VEXxy:**
- It's free (no budget)
- SBOM-focused (not VEX-focused)
- Don't need K8s-specific features
- Already invested in Dependency-Track

**How to reposition if you're losing:**
"You can use both: Dependency-Track for SBOM tracking, VEXxy for VEX management. They're complementary."

---

## Battle Card: Wiz / Orca / Prisma Cloud

### Overview
- **What they do:** Comprehensive cloud security platforms (CSPM, CWPP, KSPM, etc.)
- **Target market:** Large enterprises, multi-cloud environments
- **Pricing:** $100K-500K+/year
- **Strengths:** Comprehensive, well-funded, strong sales teams, broad security coverage
- **Weaknesses:** VEX is not a focus, expensive, "black box" (not open source)

### When You're Competing

**Likely scenario:** Prospect says, "We already use Wiz for container security. Why do we need VEXxy?"

**Your response:**

"That's great—Wiz is an excellent platform for broad cloud security. But here's the thing: **we're not competing with Wiz, we're complementary.**

Wiz focuses on:
- Cloud security posture management (CSPM)
- Workload protection (CWPP)
- High-level dashboards and risk scoring

VEXxy specializes in:
- Deep VEX management with hierarchical scoping
- Reachability-based VEX (proof of non-exploitability)
- Multi-scanner aggregation

Many customers use both:
- **Wiz:** Broad cloud security and compliance
- **VEXxy:** Deep VEX management and false positive reduction

**We integrate with Wiz.** In fact, we can ingest Wiz's vulnerability findings and enrich them with 20+ additional sources Wiz doesn't have.

Plus, VEXxy is 10-20x cheaper and open source."

### Feature Comparison

| Feature | VEXxy | Wiz/Orca/Prisma |
|---------|:-----:|:---------------:|
| VEX management (deep) | ✅ | ❌ (Basic/none) |
| Reachability VEX | ✅ | Partial (Wiz) |
| CSPM | ❌ | ✅ |
| CWPP | ❌ | ✅ |
| Open source | ✅ | ❌ |
| Multi-scanner support | ✅ | ❌ (Single vendor) |
| Price (annual) | $5K-150K | $100K-500K+ |
| VEX-specific features | ✅ (Core focus) | ❌ (Not focus) |

### Landmine Questions

1. "Does Wiz provide detailed VEX statement management with hierarchical scoping?"
   - **Why:** No, it's broad not deep

2. "Can you export VEX from Wiz in OpenVEX or CycloneDX VEX format?"
   - **Why:** Limited VEX export capabilities

3. "Do you use multiple scanners (Trivy, Grype, etc.)? Can Wiz aggregate and enrich results from all of them?"
   - **Why:** Wiz is single-vendor, we're multi-scanner

4. "How much are you paying for Wiz annually?"
   - **Why:** Sticker shock, VEXxy is 10x cheaper

### Win/Loss Intel

**Why customers choose VEXxy over Wiz/Orca/Prisma:**
- ✅ Need VEX-specific features (platforms don't prioritize this)
- ✅ Budget constraints (VEXxy 10-20x cheaper)
- ✅ Open source preference (transparency)
- ✅ Multi-scanner environments

**Why customers choose Wiz/Orca/Prisma over VEXxy:**
- They want all-in-one cloud security (CSPM + CWPP + more)
- They have large security budgets
- They want turnkey solution with big vendor support

**How to reposition if you're losing:**
"We're not asking you to replace Wiz. Use Wiz for cloud security, VEXxy for VEX management. We integrate with Wiz. Think of us as a specialized module that makes Wiz better."

---

## Battle Card: GitHub Advanced Security / GitLab Ultimate

### Overview
- **What they do:** Integrated security features in CI/CD platforms (SAST, DAST, dependency scanning, secrets detection)
- **Target market:** Development teams using GitHub/GitLab
- **Pricing:** $49/user/mo (GitHub), $99/user/mo (GitLab)
- **Strengths:** Integrated into workflow, no new tool adoption, good for shift-left
- **Weaknesses:** CI/CD-focused (not runtime), limited VEX, no centralized management, per-user pricing scales badly

### When You're Competing

**Likely scenario:** Prospect says, "GitHub Advanced Security does vulnerability scanning. Why do we need VEXxy?"

**Your response:**

"GitHub Advanced Security is great for shift-left security—finding vulnerabilities before deployment. But there's a key difference:

**GitHub scans:** Code and dependencies in CI/CD (pre-deployment)
**VEXxy manages:** Vulnerabilities in running containers across production clusters (post-deployment)

Here's a typical workflow:
1. GitHub finds vulnerabilities in your PR
2. You fix critical ones and deploy
3. VEXxy tracks vulnerabilities in your deployed images across 20 clusters
4. VEXxy helps you create VEX statements for false positives
5. VEXxy monitors new CVEs affecting your running infrastructure

**They're complementary, not competitive:**
- GitHub: Pre-deployment security (CI/CD)
- VEXxy: Post-deployment VEX management (production)

Plus:
- GitHub pricing is per-user ($49/user/mo × 100 devs = $58K/year)
- VEXxy pricing is per-cluster ($5K-10K/year for entire org)

Many customers use both. In fact, we can integrate: GitHub scans in CI/CD → VEXxy manages VEX in production."

### Feature Comparison

| Feature | VEXxy | GitHub Advanced Security |
|---------|:-----:|:------------------------:|
| CI/CD scanning | Via integration | ✅ (Core feature) |
| Runtime vulnerability mgmt | ✅ (Core feature) | ❌ |
| VEX management | ✅ (Advanced) | Basic |
| Multi-cluster centralization | ✅ | ❌ |
| Deployment tracking | ✅ | ❌ |
| Reachability VEX | ✅ (Ultimate) | ❌ |
| Pricing model | Per-cluster | Per-user |
| Typical annual cost | $5K-150K | $50K-120K (100 users) |

### Landmine Questions

1. "Does GitHub give you visibility into vulnerabilities across all your deployed clusters?"
   - **Why:** No, it's CI/CD-focused

2. "How do you create VEX statements for vulnerabilities GitHub finds?"
   - **Why:** Limited VEX support

3. "How much are you paying for GitHub Advanced Security per year?"
   - **Why:** Per-user pricing gets expensive fast

4. "Can GitHub prove that a vulnerability in production isn't reachable?"
   - **Why:** No runtime analysis

### Win/Loss Intel

**Why customers choose VEXxy over GitHub/GitLab:**
- ✅ Need runtime VEX management (not just CI/CD)
- ✅ Need centralized view across deployed clusters
- ✅ Per-cluster pricing cheaper than per-user for large teams
- ✅ Need reachability analysis in production

**Why customers choose GitHub/GitLab over VEXxy:**
- They only care about shift-left (pre-deployment)
- They don't want to adopt another tool
- They're already paying for GitHub/GitLab anyway

**How to reposition if you're losing:**
"We're not asking you to replace GitHub. Keep using it for CI/CD scanning. Add VEXxy for production VEX management. They work together."

---

## Battle Card: "We'll Build It Ourselves"

### Overview
- **What they do:** Internal engineering team builds custom VEX management
- **Target market:** Large tech companies with significant engineering resources
- **Pricing:** $0 upfront (but hidden costs)
- **Strengths:** Fully customized, no vendor dependency, control
- **Weaknesses:** Time to value (6-12 months), maintenance burden, not core competency

### When You're Competing

**Likely scenario:** Prospect says, "We have a strong engineering team. We'll just build this internally."

**Your response:**

"I respect that—you clearly have talented engineers. Let's think through the math:

**Build option:**
- Time to MVP: 3-6 months (1-2 engineers)
- Time to feature parity with VEXxy: 6-12 months (2-3 engineers)
- Cost: $150K/engineer × 2 × 0.5 year = $150K-300K
- Ongoing maintenance: $100K-200K/year (1 engineer 50% time)
- Opportunity cost: What else could those engineers build (core product features, revenue-generating work)?

**VEXxy option:**
- Time to value: 1 day (deploy and run)
- Cost: $5K-150K/year depending on tier
- Maintenance: $0 (we handle it)
- Opportunity cost: $0 (your engineers work on core product)

**Break-even: Year 1-2, then VEXxy is cheaper every year after.**

Plus:
- VEXxy is open source—you could fork and customize if needed
- We have 20+ integrations already built (NVD, EPSS, distro trackers, etc.)
- We maintain standards compliance (OpenVEX, CycloneDX, CSAF)
- We have reachability VEX (very hard to build)

**Question:** Is VEX management your core competency and competitive advantage? If not, why build it?"

### Key Points to Emphasize

1. **Time to value**
   - Build: 6-12 months
   - VEXxy: 1 day

2. **Total cost of ownership**
   - Build: $150K-300K upfront, $100K-200K/year ongoing
   - VEXxy: $5K-150K/year all-in

3. **Maintenance burden**
   - Build: Your team maintains forever (integration updates, standards changes, bug fixes)
   - VEXxy: We maintain, you benefit

4. **Feature velocity**
   - Build: Slow (your team has other priorities)
   - VEXxy: Fast (our team's only job)

5. **Opportunity cost**
   - Build: Engineers not working on core product
   - VEXxy: Engineers focused on competitive advantage

6. **Risk**
   - Build: What if the engineer who built it leaves?
   - VEXxy: No key person risk

### Landmine Questions

1. "How long will it take your team to build feature parity with VEXxy?"
   - **Why:** 6-12 months vs. our 1 day

2. "Who will maintain it after it's built?"
   - **Why:** Ongoing burden

3. "What's the opportunity cost? What else could those engineers build?"
   - **Why:** Highlight competing priorities

4. "Is VEX management your competitive advantage?"
   - **Why:** If no, why build?

5. "Have you calculated total cost including maintenance?"
   - **Why:** Hidden costs add up

6. "Can you build reachability analysis (sandbox, profiling, fuzzing)?"
   - **Why:** Very hard, security-critical

### Win/Loss Intel

**Why customers choose VEXxy over building:**
- ✅ Time to value (need VEX now, not in 6 months)
- ✅ Total cost (building is more expensive)
- ✅ Not core competency (focus on product)
- ✅ Reachability VEX is hard to build

**Why customers choose to build:**
- They have very specific custom requirements
- They have excess engineering capacity
- They underestimate maintenance burden (will regret later)

**How to reposition if you're losing:**
"That's fine. But even if you build, consider using VEXxy's open-source core as a starting point. Why reinvent the wheel? Fork it, customize it, contribute back."

---

## General Competitive Messaging

### Positioning Statement

"VEXxy is the only platform that combines centralized VEX management with empirical reachability analysis. We work with any scanner, any image, any registry. We're open source with enterprise tiers for scale, compliance, and automation. We're deep on VEX, not broad on cloud security."

### Key Differentiators (Memorize These)

1. **Reachability VEX (Ultimate tier)**
   - Only platform that proves vulnerability non-exploitability with runtime analysis
   - Sandbox + profiling + fuzzing + evidence

2. **Multi-scanner support**
   - Works with Trivy, Grype, Snyk, or any scanner
   - Not locked to single vendor

3. **Open source**
   - Apache 2.0 license
   - No vendor lock-in
   - Transparent, auditable code

4. **20+ enrichment sources**
   - Most comprehensive vulnerability intelligence
   - NVD, EPSS, KEV, distro trackers, cloud providers, language ecosystems

5. **Kubernetes-native**
   - Built for K8s from day one
   - Deployment-aware, cluster/namespace/workload tracking

6. **VEX-specialized**
   - Our core focus, not a side feature
   - Hierarchical scoping, versioning, impact analysis

### When to Walk Away

**Don't waste time on:**
- Companies with <3 clusters (too small)
- Companies with 1-2 person engineering team (no budget)
- Companies that want features we'll never build (e.g., CSPM, EDR)
- Companies that are "just researching" with no timeline
- Companies where you can't reach economic buyer

**Politely exit:**
"Thanks for your time. Based on what you've shared, I don't think VEXxy is the right fit right now. Here are some resources on VEX best practices. Feel free to reach out if things change!"

---

## Quick Reference: Competitive Positioning

| Competitor | One-Liner Position |
|------------|-------------------|
| **Chainguard** | "We work with ANY image, not just Chainguard images. No vendor lock-in." |
| **Anchore** | "We're complementary. Use Grype for scanning, VEXxy for VEX management." |
| **Dependency-Track** | "We're Kubernetes-native with advanced VEX. They're SBOM-focused." |
| **Wiz/Orca/Prisma** | "We're complementary. They do broad cloud security, we specialize in VEX." |
| **GitHub/GitLab** | "They do CI/CD (pre-deployment), we do production VEX (post-deployment)." |
| **Build Ourselves** | "Build takes 6-12 months + ongoing maintenance. VEXxy works in 1 day." |

---

**Document Owner:** Sales Team
**Last Updated:** November 2025
**Next Review:** Quarterly (update based on competitive intelligence)

**Remember:** Never trash competitors. Position based on value and fit, not "we're better."
