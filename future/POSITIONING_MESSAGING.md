# VEXxy: Positioning & Messaging Guide

**Version:** 1.0
**Date:** November 2025
**Audience:** Marketing, Sales, Partners

---

## Table of Contents

1. [Brand Positioning](#brand-positioning)
2. [Core Messaging](#core-messaging)
3. [Value Propositions by Audience](#value-propositions-by-audience)
4. [Messaging Framework](#messaging-framework)
5. [Content Pillars](#content-pillars)
6. [Voice & Tone](#voice--tone)
7. [Marketing Copy Library](#marketing-copy-library)
8. [Competitive Differentiation](#competitive-differentiation)

---

## Brand Positioning

### Positioning Statement

**For** security-conscious organizations running Kubernetes at scale
**Who** are drowning in vulnerability alerts and need VEX statements for compliance
**VEXxy is** an open-core VEX management platform
**That** reduces alert fatigue by 70-90% through intelligent prioritization and automated reachability analysis
**Unlike** general-purpose security platforms or single-scanner solutions
**VEXxy** provides centralized, evidence-based vulnerability management with the industry's only reachability-based VEX generation.

### Brand Promise

**"Prove what matters. Ignore the noise."**

We help security teams focus on vulnerabilities that actually pose risk, with empirical proof that others don't.

### Category

**Primary:** VEX Management Platform
**Secondary:** Vulnerability Intelligence Platform
**Adjacent:** Container Security, Kubernetes Security, SBOM Management

**Category creation:** We're defining "VEX Management Platform" as a new category (like how Datadog defined "observability").

---

## Core Messaging

### Headline Options

**Default (Technical):**
"The Open-Source VEX Management Platform for Kubernetes"

**Alternative (Problem-focused):**
"Stop Drowning in Vulnerability Alerts. Start Managing VEX with Confidence."

**Alternative (Outcome-focused):**
"70-90% Fewer False Positives. Empirical Proof. Automated Compliance."

**Alternative (Differentiation-focused):**
"The Only VEX Platform That Proves Vulnerability Reachability"

### Tagline Options

1. **"Prove what matters. Ignore the noise."** ← RECOMMENDED
2. "From alerts to action, with proof"
3. "Centralize VEX. Eliminate false positives."
4. "VEX management for the real world"
5. "Evidence-based vulnerability prioritization"

### Elevator Pitch (30 seconds)

"VEXxy is an open-source platform that helps security teams manage vulnerability exploitability across Kubernetes environments. We centralize VEX statements from all your scanners, enrich them with 20+ intelligence sources, and automatically detect false positives. Our Ultimate tier goes further: we spin up sandboxes to analyze runtime behavior and prove which vulnerabilities aren't reachable. The result? 70-90% fewer alerts with compliance-ready evidence. It's like having a security analyst working 24/7 to triage your vulnerabilities."

### Elevator Pitch (60 seconds)

"Most organizations running Kubernetes get 10,000+ vulnerability alerts every month. 70-95% are false positives—vulnerabilities that aren't actually exploitable in your specific context. Triaging these manually is expensive and error-prone.

VEXxy solves this with three innovations:

First, we centralize VEX statements across all your clusters and scanners, giving you a single source of truth. No more spreadsheets.

Second, we enrich every vulnerability with 20+ intelligence sources—NVD, EPSS, distro security trackers, cloud providers—and automatically detect false positives using pattern recognition and scanner consensus.

Third, and unique to VEXxy: we offer reachability-based VEX. We spin up your container in a sandbox, run profiling and fuzzing, and empirically prove which vulnerability code paths are never executed. It's the difference between 'I think this is safe' and 'I can prove this is safe.'

We're open-source with enterprise tiers for multi-tenancy, SSO, integrations, and that reachability analysis. We help you focus on the 5-10% of vulns that actually matter."

---

## Value Propositions by Audience

### CISO / VP Security (Economic Buyer)

**Primary Value:**
"Reduce security risk and analyst burden by 70-90% while meeting VEX compliance requirements."

**Key Messages:**
- ✅ **Risk reduction:** Focus resources on real threats, not false alarms
- ✅ **Cost efficiency:** $90K/year wasted per analyst on false positives—we eliminate most of that
- ✅ **Compliance ready:** Meet US EO 14028, EU Cyber Resilience Act VEX requirements
- ✅ **Board reporting:** Clear metrics on vulnerability remediation with evidence
- ✅ **Future-proof:** As VEX regulations expand, you're already compliant

**Pain Points Addressed:**
- "I can't tell if we're actually secure or just have fewer alerts"
- "Auditors keep asking for VEX documents and we don't have a process"
- "My security team is burned out from alert fatigue"

### Security Engineering Lead (Technical Buyer)

**Primary Value:**
"Centralized, intelligent VEX management that integrates with your existing tools and provides actionable insights."

**Key Messages:**
- ✅ **Centralization:** One platform for all clusters, scanners, and teams
- ✅ **Intelligence:** 20+ enrichment sources provide context for every CVE
- ✅ **Automation:** False positive detection, auto-VEX suggestions, bulk operations
- ✅ **Integration:** Works with Trivy, Grype, Jira, Slack, ServiceNow, etc.
- ✅ **Flexibility:** Open-source core means no vendor lock-in

**Pain Points Addressed:**
- "We have Trivy in some clusters, Grype in others, and no central view"
- "I spend hours researching whether a CVE is actually exploitable"
- "Our VEX process is a spreadsheet and manual work"

### DevSecOps Engineer (End User)

**Primary Value:**
"Automated vulnerability triage with empirical proof, so you focus on fixing real issues, not chasing ghosts."

**Key Messages:**
- ✅ **Time savings:** 10x faster VEX creation (automated vs. manual)
- ✅ **Accuracy:** Reachability analysis proves vulnerabilities aren't exploitable
- ✅ **Context:** Every vuln enriched with distro patches, exploit availability, etc.
- ✅ **Easy to use:** Modern UI, clear workflows, keyboard shortcuts
- ✅ **Developer-friendly:** API-first, CLI tools, CI/CD integration

**Pain Points Addressed:**
- "I get pinged about CVEs that don't even affect our code paths"
- "Validating false positives takes 30-60 minutes per CVE"
- "I'm constantly context-switching between security tools"

### VP Engineering (Influencer/Approver)

**Primary Value:**
"Free up engineering time by eliminating false positive vulnerability noise while maintaining security posture."

**Key Messages:**
- ✅ **Developer productivity:** Reduce security-related interruptions by 70-90%
- ✅ **Delivery speed:** Fewer false positives = faster deployments
- ✅ **Team morale:** Less burnout from meaningless security work
- ✅ **Customer trust:** Demonstrate security with evidence-based VEX
- ✅ **Competitive advantage:** Meet compliance requirements faster than competitors

**Pain Points Addressed:**
- "Security slows down our releases with false alarms"
- "Customers ask for VEX documents and we scramble"
- "My team hates security tools because of false positives"

### Compliance Officer / Auditor (Secondary Audience)

**Primary Value:**
"Auditable, evidence-based VEX documentation that proves vulnerability management due diligence."

**Key Messages:**
- ✅ **Traceability:** Every VEX decision documented with justification and evidence
- ✅ **Standards compliance:** OpenVEX, CycloneDX, CSAF format support
- ✅ **Audit-ready:** Export VEX statements and reports on demand
- ✅ **Immutable audit logs:** Track who made what decisions when (Enterprise)
- ✅ **Evidence-based:** Reachability analysis provides empirical proof (Ultimate)

**Pain Points Addressed:**
- "How do you know this vulnerability isn't exploitable?"
- "Show me your VEX documentation for this component"
- "What's your process for vulnerability assessment?"

---

## Messaging Framework

### Problem → Agitate → Solution (PAS)

**Problem:**
Organizations running Kubernetes receive thousands of vulnerability alerts monthly. 70-95% are false positives that waste analyst time and create burnout.

**Agitate:**
Security teams spend 60% of their time chasing false positives. That's $90K per analyst per year. Meanwhile, real vulnerabilities slip through the noise. New regulations require VEX documents, but most teams manage VEX in spreadsheets or not at all.

**Solution:**
VEXxy centralizes VEX management, enriches vulnerabilities with 20+ intelligence sources, automatically detects false positives, and—uniquely—proves vulnerability reachability through runtime analysis. Reduce alert fatigue by 70-90% while meeting compliance requirements.

### Before → After → Bridge (BAB)

**Before (Current State):**
- Vulnerability alerts scattered across scanners and clusters
- Manual triage taking hours per CVE
- No central VEX documentation
- Security team drowning in false positives
- Can't prove vulnerabilities are non-exploitable for audits

**After (Desired State):**
- Single source of truth for all vulnerability and VEX data
- Automated triage with false positive detection
- Compliance-ready VEX documents with evidence
- Security team focused on real threats
- Empirical proof that vulnerabilities aren't reachable

**Bridge (How VEXxy Gets You There):**
VEXxy provides open-source centralized VEX management, intelligent enrichment from 20+ sources, automated false positive detection, and optional reachability analysis that proves vulnerability exploitability with sandbox testing.

### Feature → Advantage → Benefit (FAB)

| Feature | Advantage | Benefit |
|---------|-----------|---------|
| Centralized VEX management | Single pane of glass for all clusters/scanners | Save 10+ hours/week consolidating reports |
| 20+ enrichment sources | Comprehensive context for every CVE | Make triage decisions in seconds, not hours |
| False positive detection | Pattern-based + ML-powered detection | Reduce false positives by 70-90% |
| Reachability VEX (Ultimate) | Runtime analysis proves unreachability | Eliminate false positives with empirical proof |
| Open-source core | No vendor lock-in, transparent code | Build trust, customize to your needs |
| Multi-scanner support | Works with Trivy, Grype, etc. | No need to rip and replace existing tools |
| Hierarchical scoping | VEX at global, project, cluster, namespace, workload levels | Fine-grained control for complex organizations |

---

## Content Pillars

### 1. Vulnerability Alert Fatigue (Pain-Focused)

**Topics:**
- "Why 95% of Your Vulnerability Alerts Are Noise"
- "The Hidden Cost of False Positives: $90K Per Analyst"
- "Alert Fatigue Is Burning Out Your Security Team"
- "How to Triage 10,000 Vulnerabilities Without Going Insane"

**Goal:** Establish pain, position VEXxy as solution

### 2. VEX Standards & Compliance (Educational)

**Topics:**
- "What Is VEX? A Complete Guide for Security Teams"
- "US Executive Order 14028: What It Means for Your VEX Process"
- "EU Cyber Resilience Act: VEX Requirements Explained"
- "OpenVEX vs. CycloneDX VEX vs. CSAF: Which Format Should You Use?"

**Goal:** Educate market, establish thought leadership

### 3. False Positive Detection (Technical)

**Topics:**
- "5 Ways to Detect False Positive Vulnerabilities"
- "Using Distro Security Trackers to Validate CVE Fixes"
- "Scanner Consensus: Why You Should Never Trust One Tool"
- "The Science of Reachability Analysis"

**Goal:** Demonstrate technical depth, differentiate

### 4. Kubernetes Security Best Practices (SEO)

**Topics:**
- "Container Image Security: A Practical Guide"
- "How to Implement Seccomp Profiles in Kubernetes"
- "SBOM Management for Kubernetes Deployments"
- "Kubernetes Vulnerability Scanning: Tools Comparison"

**Goal:** Drive organic traffic, establish authority

### 5. VEXxy Product & Features (Product Marketing)

**Topics:**
- "Introducing VEXxy: Open-Source VEX Management"
- "How VEXxy's Reachability Analysis Works"
- "VEXxy vs. [Competitor]: Feature Comparison"
- "Customer Story: How [Company] Reduced Alerts by 85%"

**Goal:** Product awareness, lead generation

---

## Voice & Tone

### Brand Personality

**Professional, but not stuffy**
- We're serious about security, but approachable
- Technical depth without jargon overload
- Confident but not arrogant

**Helpful, not salesy**
- Educate first, sell second
- Provide value even to non-customers
- Share knowledge openly (open-source ethos)

**Evidence-based, not hyperbolic**
- Use real data and case studies
- Avoid marketing superlatives ("revolutionary", "game-changing")
- Let the product speak for itself

### Voice Characteristics

**✅ DO:**
- Use active voice ("VEXxy reduces alerts by 90%")
- Use concrete numbers and data
- Use "we" and "you" (conversational)
- Explain technical concepts clearly
- Acknowledge trade-offs and alternatives

**❌ DON'T:**
- Use passive voice ("Alerts are reduced by VEXxy")
- Make vague claims ("significantly improves")
- Use third person ("VEXxy users will find...")
- Use buzzwords without explanation
- Pretend there are no alternatives

### Tone by Context

| Context | Tone | Example |
|---------|------|---------|
| **Homepage** | Confident, clear | "The open-source VEX management platform that proves what matters." |
| **Blog posts** | Educational, helpful | "Let's walk through how reachability analysis works under the hood." |
| **Documentation** | Precise, concise | "To enable SSO, set the `SAML_ENABLED` environment variable to `true`." |
| **Sales emails** | Consultative, direct | "I noticed you're using Trivy—VEXxy can centralize those scans across your clusters." |
| **Social media** | Casual, engaging | "Hot take: If you're manually triaging 10K vulns/month, you're doing it wrong. Here's a better way: 🧵" |
| **Error messages** | Apologetic, helpful | "Oops! That API key is invalid. Double-check the format or create a new one here: [link]" |

---

## Marketing Copy Library

### Website Copy

#### Homepage Hero

**Headline:**
"The Open-Source VEX Management Platform for Kubernetes"

**Subheadline:**
"Reduce vulnerability alert fatigue by 70-90%. Prove what matters with reachability analysis. Stay compliant with automated VEX generation."

**CTA:**
[Start Free Trial] [Download Open Source] [Watch Demo]

**Social Proof:**
"Trusted by security teams at [Logo] [Logo] [Logo]"

#### Features Section

**Feature 1: Centralized Management**
**Headline:** "One Platform for All Your Clusters"
**Body:** "Stop juggling spreadsheets and scattered scan results. VEXxy centralizes vulnerability and VEX data from all your Kubernetes clusters and scanners into a single source of truth."

**Feature 2: Intelligent Enrichment**
**Headline:** "20+ Intelligence Sources in Seconds"
**Body:** "Every vulnerability enriched with NVD, EPSS, KEV, distro security trackers, and cloud provider advisories. Make informed decisions with complete context."

**Feature 3: False Positive Detection**
**Headline:** "Automatically Filter the Noise"
**Body:** "Pattern-based detection, scanner consensus analysis, and distro validation catch false positives before they reach your team. Focus on what actually matters."

**Feature 4: Reachability VEX (Ultimate)**
**Headline:** "Prove Vulnerabilities Aren't Exploitable"
**Body:** "Runtime analysis in isolated sandboxes. OWASP ZAP fuzzing. Empirical evidence that vulnerable code paths are never executed. The industry's only reachability-based VEX generation."

#### Use Cases

**Use Case 1: Security Teams**
**Headline:** "Reduce Alert Fatigue by 70-90%"
**Body:** "Stop wasting 60% of your time on false positives. VEXxy's intelligent triage helps you focus on vulnerabilities that pose real risk."

**Use Case 2: Compliance Teams**
**Headline:** "Meet VEX Requirements with Confidence"
**Body:** "US EO 14028, EU Cyber Resilience Act, and customer security questionnaires all require VEX. VEXxy provides audit-ready documentation with evidence."

**Use Case 3: DevOps Teams**
**Headline:** "Ship Faster Without Compromising Security"
**Body:** "Fewer false positives mean fewer blocked deployments. Automated VEX statements mean less back-and-forth with security teams."

### Email Copy

#### Cold Outreach Email (Personalized)

**Subject:** Quick question about your Trivy scans

**Body:**
Hi [First Name],

I noticed [Company] is using Trivy for container scanning (saw your job posting for a DevSecOps engineer). Quick question: how are you managing VEX statements across your clusters?

Most teams we talk to are either:
1. Managing VEX in spreadsheets (time-consuming)
2. Not creating VEX at all (compliance risk)
3. Creating VEX manually per-scan (doesn't scale)

VEXxy is an open-source platform that centralizes VEX management. It works with your existing Trivy setup and automatically detects false positives using 20+ intelligence sources.

Worth a 15-minute demo to see if it could save your team time?

[Calendar Link]

Best,
[Your Name]

P.S. We're open source (Apache 2.0), so you can try it without talking to sales: [GitHub Link]

#### Nurture Email (Educational)

**Subject:** [Blog Post] Why 95% of Your Vulnerability Alerts Are Noise

**Body:**
Hi [First Name],

New blog post you might find useful: **Why 95% of Your Vulnerability Alerts Are Noise (And What to Do About It)**

[Blog Link]

TL;DR:
• Most vulnerability scanners report every CVE in every component
• 70-95% don't apply to your specific configuration
• Triaging these manually costs $90K per analyst per year
• There's a better way: automated false positive detection

If you're drowning in vulnerability alerts, this is worth 5 minutes of your time.

-[Your Name]

P.S. VEXxy is our open-source tool for solving this. Check it out if you're interested: [GitHub Link]

### Social Media Copy

#### LinkedIn Post (Thought Leadership)

Hot take: Most vulnerability scanners are broken by design.

Here's why:

They report EVERY CVE in EVERY component, regardless of whether:
- The vulnerable function is called by your code
- The vulnerability applies to your OS/distro version
- You've already patched it via distro security updates

The result? 10,000+ alerts per month, 95% false positives.

Security teams spend 60% of their time chasing ghosts.

The solution isn't better scanners. It's better intelligence AFTER scanning:

1️⃣ Enrichment (distro trackers, EPSS, KEV)
2️⃣ Context (is this code path reachable?)
3️⃣ Automation (VEX statements with proof)

That's what we built with VEXxy (open source):
[Link]

What's your false positive rate? Comment below 👇

---

#### Twitter Thread Starter

🧵 Thread: Why your security team is drowning in vulnerability alerts (and how to fix it)

1/ Most orgs running Kubernetes get 10,000+ vulnerability alerts per month.

95% are false positives.

Your security team spends 60% of their time proving vulnerabilities don't apply.

That's $90K/year per analyst. On noise.

Here's why this happens... [1/10]

---

#### Reddit Post (r/kubernetes)

**Title:** [Open Source] We built a VEX management platform for Kubernetes

**Body:**
Hi r/kubernetes,

We just open-sourced VEXxy, a platform for managing VEX (Vulnerability Exploitability eXchange) statements across Kubernetes clusters.

**The problem we're solving:**
- You have Trivy or Grype scanning your images
- You get thousands of CVE alerts every month
- 70-95% are false positives (OS packages, vendor patches, unreachable code)
- Triaging them manually is soul-crushing

**What VEXxy does:**
- Centralizes vulnerability data from all your clusters and scanners
- Enriches each CVE with 20+ intelligence sources (NVD, EPSS, distro trackers, etc.)
- Automatically detects false positives using pattern matching and scanner consensus
- Helps you create VEX statements (documenting which CVEs don't apply and why)
- Exports VEX in OpenVEX, CycloneDX, or CSAF formats

**Tech stack:**
- Backend: FastAPI (async), PostgreSQL, Redis, Celery
- Frontend: React 19, TypeScript, TanStack Query
- Deployment: Docker, Kubernetes (Helm chart coming soon)

**License:** Apache 2.0

**Repo:** [GitHub link]

We're also building an enterprise tier with reachability analysis (spin up sandboxes, run profiling, prove which code paths are never executed). But the core platform is fully open source.

Would love feedback from the community!

---

### Ad Copy

#### Google Ads (Search)

**Headline 1:** VEX Management for Kubernetes
**Headline 2:** Reduce Alerts by 70-90%
**Headline 3:** Open Source + Enterprise Support

**Description:** Centralized VEX management with false positive detection. Works with Trivy, Grype, and more. Start free. [URL]

---

#### LinkedIn Ads (Sponsored Content)

**Headline:** Stop Wasting Time on False Positive Vulnerabilities

**Body:** Security teams spend 60% of their time chasing vulnerability alerts that don't apply. VEXxy's intelligent triage and reachability analysis eliminates 70-90% of false positives.

**CTA:** See How It Works

---

## Competitive Differentiation

### vs. Chainguard

**When to use:**
"Unlike Chainguard, which only provides VEX for their own hardened images, VEXxy works with ANY container image from any registry. You're not locked into a single vendor's image catalog."

**When they say:** "Chainguard has reachability analysis too"
**You say:** "Yes, but only for Chainguard images. VEXxy provides reachability VEX for arbitrary images—your existing images, third-party images, anything. Plus we're open source."

### vs. Anchore (Grype/Syft)

**When to use:**
"Anchore's strength is scanning and SBOM generation. VEXxy is purpose-built for VEX management across multiple scanners, including Anchore's tools. We're complementary—use Grype for scanning, VEXxy for VEX management."

**When they say:** "Grype has VEX support"
**You say:** "Yes, Grype can consume VEX documents. But managing VEX at scale—across clusters, teams, and time—requires a dedicated platform. That's VEXxy's focus."

### vs. Dependency-Track

**When to use:**
"Dependency-Track is great for SBOM-centric workflows, but it's not Kubernetes-native and has limited VEX capabilities. VEXxy is built specifically for K8s environments with deployment-aware vulnerability management and advanced VEX."

**When they say:** "Dependency-Track is free and mature"
**You say:** "True, and it's a solid OWASP project. VEXxy is also open source (Apache 2.0) but offers modern UX, K8s-native design, and features like reachability VEX that Dependency-Track doesn't have."

### vs. Wiz/Orca/Prisma

**When to use:**
"If you're using Wiz or Prisma Cloud for CSPM/CWPP, that's great—keep using them! VEXxy specializes in VEX management, which those platforms don't focus on. We integrate with them. Think of us as complementary, not competitive."

**When they say:** "Wiz covers container security"
**You say:** "Absolutely, and Wiz is excellent for broad cloud security. But when it comes to deep VEX management—hierarchical scoping, reachability analysis, multi-scanner aggregation—that's where VEXxy excels. We're 10x cheaper too."

### vs. GitHub Advanced Security

**When to use:**
"GitHub Advanced Security is great for shift-left security in CI/CD. VEXxy is for runtime vulnerability management across deployed Kubernetes infrastructure. Many customers use both: GitHub for pre-deployment, VEXxy for post-deployment."

**When they say:** "GitHub already does vulnerability scanning"
**You say:** "Yes, in CI/CD. But what about the 10,000 containers already running in production across your clusters? VEXxy gives you visibility and VEX management for your entire runtime environment."

---

## Messaging Do's and Don'ts

### ✅ DO

- **Lead with pain:** "Are you drowning in vulnerability alerts?"
- **Use specific numbers:** "70-90% reduction" not "significant reduction"
- **Provide evidence:** Case studies, customer quotes, data
- **Acknowledge alternatives:** "If you're using Wiz, we complement them"
- **Be honest about limitations:** "Reachability analysis requires sandbox infrastructure"
- **Use customer language:** "Alert fatigue" not "signal-to-noise ratio optimization"

### ❌ DON'T

- **Oversell:** Avoid "revolutionary", "game-changing", "industry-first" (unless true)
- **Trash competitors:** Never say "Chainguard is bad"—say "VEXxy offers more flexibility"
- **Use unexplained jargon:** Define terms like VEX, SBOM, CVE on first use
- **Make unsubstantiated claims:** "Best VEX platform" without proof
- **Be vague:** "Improves security" → "Reduces false positives by 85% (avg customer)"
- **Ignore open source:** Don't hide that we're open-core—it's a strength!

---

## Messaging Testing & Iteration

**A/B test these variables:**
- Headline: Problem-focused vs. solution-focused
- CTA: "Start free trial" vs. "Download open source"
- Proof: Customer logos vs. GitHub stars count
- Feature emphasis: Centralization vs. reachability VEX

**Track these metrics:**
- Click-through rate (CTR) on different headlines
- Conversion rate by messaging variant
- Bounce rate on landing pages
- Demo request rate by campaign

**Monthly messaging review:**
- What resonates with customers in sales calls?
- What objections come up repeatedly?
- What language do customers use to describe problems?
- Adjust messaging to reflect learnings

---

## Appendix: Keyword Research

### Primary Keywords (SEO)
- VEX management
- VEX platform
- Vulnerability exploitability exchange
- SBOM compliance
- Kubernetes vulnerability management
- Container security VEX
- False positive vulnerability detection

### Long-Tail Keywords
- How to create VEX statements
- OpenVEX vs CycloneDX VEX
- Kubernetes vulnerability scanner comparison
- Reduce false positive vulnerabilities
- VEX compliance US executive order
- Reachability analysis vulnerability

### Competitor Keywords
- Chainguard alternative
- Grype VEX management
- Dependency-Track Kubernetes
- Anchore enterprise alternative

---

**Document Owner:** Marketing Team
**Last Updated:** November 2025
**Next Review:** Q1 2026 (after initial campaign results)

**Usage:** This document should guide all customer-facing content, from website copy to sales decks to social media posts. When in doubt, refer back to the brand voice, core messaging, and value propositions defined here.
