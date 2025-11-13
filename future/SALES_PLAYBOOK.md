# VEXxy Sales Playbook

**Version:** 1.0
**Date:** November 2025
**For:** Founder, Sales Team, Partners

---

## Table of Contents

1. [Sales Process Overview](#sales-process-overview)
2. [Qualification Framework (MEDDIC)](#qualification-framework-meddic)
3. [Discovery Call Script](#discovery-call-script)
4. [Demo Script](#demo-script)
5. [Objection Handling](#objection-handling)
6. [Closing Techniques](#closing-techniques)
7. [Email Templates](#email-templates)
8. [Pricing & Negotiation](#pricing--negotiation)
9. [Champion Building](#champion-building)

---

## Sales Process Overview

### Sales Funnel by Tier

#### Self-Serve (SaaS Free → Paid)
```
Sign up → Onboarding → Value realization → Upgrade prompt → Paid
```
**Typical timeline:** 7-30 days
**Conversion rate:** 5-10%
**No human touch** until upgrade or support request

#### Low-Touch (Professional Tier)
```
Inbound lead → Qualification → Discovery → Demo → POC → Proposal → Close
```
**Typical timeline:** 30-60 days
**Average deal size:** $5K-15K
**Founder-led** (first 20 customers)

#### High-Touch (Enterprise Plus & Ultimate)
```
Outbound/Inbound → Multi-stakeholder discovery → Technical demo → POC →
Security review → Procurement → Legal → Close
```
**Typical timeline:** 90-180 days
**Average deal size:** $25K-150K
**Requires dedicated sales resources**

---

## Qualification Framework (MEDDIC)

Use MEDDIC to qualify every enterprise opportunity:

### M - Metrics
**What to ask:**
- How many Kubernetes clusters do you run?
- How many vulnerability alerts do you get per month?
- How much time does your team spend triaging vulnerabilities?
- What's your current false positive rate?

**Good answer:**
- 10+ clusters, 5,000+ alerts/month, 20+ hours/week on triage
- "We're drowning in alerts" or "My team is burnt out"

**Bad answer:**
- 1-2 clusters, 100 alerts/month, "It's manageable"
- Not a priority → Disqualify or nurture for later

### E - Economic Buyer
**Who approves budget for security tools?**
- CISO / VP Security (typical for $50K+ deals)
- VP Engineering (for $10K-30K deals)
- Director of Security Engineering (for $5K-20K deals)

**Key question:** "Who has budget authority for this purchase?"

**Red flag:** Can't identify economic buyer or "I need to ask"

### D - Decision Criteria
**What criteria matter for this purchase?**
- Technical: Integration with existing tools, ease of use, accuracy
- Business: ROI, time savings, compliance requirements
- Vendor: Support SLA, company stability, open source

**Key question:** "What will make or break this decision?"

### D - Decision Process
**What are the steps from here to signed contract?**
- Typical: Technical evaluation → Security review → Procurement → Legal
- Timeline: 30 days (Professional) to 180 days (Ultimate)

**Key question:** "Walk me through your typical buying process for security tools."

### I - Identify Pain
**What's the core business pain?**
- Alert fatigue: "My team is overwhelmed"
- Compliance: "We need VEX for audits"
- Efficiency: "We're wasting time on false positives"

**Key question:** "If you don't solve this, what happens?"

**Good answer:** "We'll fail our audit" or "People will quit"
**Bad answer:** "It's annoying but we'll manage"

### C - Champion
**Who internally will sell VEXxy on your behalf?**
- Typically: Security engineer, DevSecOps lead
- Must have credibility and motivation to drive deal

**Key question:** "Who else needs to be convinced? Can you introduce me?"

**Red flag:** No champion or champion lacks influence

---

## Discovery Call Script

### Pre-Call Prep (5 minutes)
- [ ] Research company (size, industry, tech stack)
- [ ] Check if they use Trivy/Grype (LinkedIn, job posts, tech blog)
- [ ] Identify who's on the call (LinkedIn profiles)
- [ ] Prepare 3-5 targeted questions

### Opening (2 minutes)

"Thanks for taking the time today. Before we dive in, let me give you a 30-second overview of VEXxy, then I'd love to hear about your current setup and challenges.

VEXxy is an open-source platform for centralized VEX management across Kubernetes environments. We help security teams reduce vulnerability alert fatigue by 70-90% through intelligent enrichment and, uniquely, reachability-based VEX generation that proves which vulnerabilities don't pose risk.

Now, I'd love to learn about your environment. Can you tell me about your current vulnerability management process?"

### Discovery Questions (15-20 minutes)

**1. Current State (Environment)**
- "How many Kubernetes clusters are you running?"
- "What scanners are you using? (Trivy, Grype, other?)"
- "How many container images do you have in production?"
- "Who's responsible for vulnerability management?"

**2. Pain Points (Problems)**
- "How many vulnerability alerts do you get per month?"
- "What percentage would you estimate are false positives?"
- "How do you currently triage and prioritize vulnerabilities?"
- "How long does it take to investigate a single CVE?"
- "What's the biggest pain point in your current process?"

**3. VEX & Compliance (Motivation)**
- "Are you creating VEX statements today? If so, how?"
- "Do you have compliance requirements around VEX? (SOC2, customer requests, etc.)"
- "Have you been asked by customers or auditors for VEX documents?"

**4. Impact (Quantify Pain)**
- "How much time per week does your team spend on vulnerability triage?"
- "How many people are involved in this process?"
- "What's that costing you? (rough calculation: X hours × $150/hr)"
- "What could your team accomplish if they had 70% of that time back?"

**5. Decision Process (MEDDIC)**
- "If we can demonstrate VEXxy solves this, what's the next step?"
- "Who else needs to be involved in the decision?"
- "What's your typical timeline for evaluating and purchasing a tool like this?"
- "What criteria matter most? (technical, pricing, support, etc.)"

### Needs Summary (3 minutes)

"Let me summarize what I heard:
- You're running [X] clusters with [Y] scanners
- You're seeing [Z] alerts per month, [%] false positives
- Your team spends [N] hours/week on triage, costing ~$[amount]
- You [do/don't] have VEX compliance requirements
- Decision involves [people], timeline is [duration]

Does that sound right?"

### Next Steps (2 minutes)

**If qualified:**
"Based on what you've shared, I think VEXxy could save your team [X] hours per week and help with [specific pain point]. The best next step is a technical demo where I'll show you:
1. How we centralize data from your scanners
2. How our false positive detection works
3. How we generate VEX statements with evidence

Does [time slot] work for you and [technical stakeholder]?"

**If not qualified:**
"Thanks for sharing your process. It sounds like you've got things under control for now. I'll send you some resources on VEX best practices, and feel free to reach out when [X trigger event] happens."

### Post-Call (5 minutes)
- [ ] Update CRM with notes (pains, metrics, decision process)
- [ ] Send calendar invite for demo
- [ ] Send follow-up email with resources
- [ ] Set reminder for follow-up if no response

---

## Demo Script

### Pre-Demo Prep (15 minutes)
- [ ] Confirm attendees and their roles
- [ ] Prepare demo environment with relevant data
- [ ] Review discovery call notes (tailor demo to their pains)
- [ ] Test demo environment (don't let technical issues derail you)

### Demo Structure (60 minutes)

#### Opening (5 minutes)

"Thanks everyone for joining. On the call today I have [names/roles]—did I get that right?

Here's how I'd like to use our time:
1. Quick recap of what we discussed [in discovery call]
2. Live demo of VEXxy (30-40 minutes)
3. Q&A and next steps (15-20 minutes)

Sound good? Any questions before we start?"

"Quick recap: You mentioned you're running [X] clusters, getting [Y] alerts/month, and spending [Z] hours on triage. Your main goals are [goals from discovery]. I'm going to show you exactly how VEXxy addresses those."

#### Demo Part 1: The Problem (5 minutes)

**Show: Dashboard with overwhelming data**

"First, let me show you what the problem looks like. Here's a typical view: 12,453 total vulnerabilities across 500 images. If your team had to triage all of these manually, you'd be here for weeks."

[Click into image with many vulns]

"Let's look at this image. 247 vulnerabilities, 89 are HIGH or CRITICAL. But here's the key question: which of these actually pose risk to YOU?"

#### Demo Part 2: Intelligence & Enrichment (10 minutes)

**Show: Vulnerability detail page with enrichment**

"This is where VEXxy differs. Let's click into CVE-2024-1234. You'll see we automatically enrich every CVE with 20+ intelligence sources:

1. **NVD data:** CVSS score, description, CWE
2. **EPSS:** Exploit prediction (0.2% chance of exploitation in next 30 days)
3. **KEV:** Not on CISA's Known Exploited Vulnerabilities list
4. **Distro tracker:** [Show Debian tracker] This was patched in Debian security update 3 weeks ago
5. **Component context:** Affects libssl3, which you have at version 3.0.8
6. **Deployment context:** This image runs in your production cluster, namespace 'api-gateway'

Now, armed with this context, you can make an informed decision in 30 seconds instead of 30 minutes of research."

#### Demo Part 3: False Positive Detection (10 minutes)

**Show: False positive analysis**

"Here's where it gets powerful. VEXxy automatically analyzes patterns to detect false positives. Let's run false positive check on this CVE."

[Click "Analyze for False Positive"]

"It's flagging this as LIKELY FALSE POSITIVE with 85% confidence. Why?

1. **Distro patch applied:** Debian security tracker shows this was fixed in your distro version
2. **Scanner disagreement:** Trivy reports this, but Grype doesn't (consensus failure)
3. **Pattern match:** Matches known false positive pattern #47 (Alpine + SSL)

VEXxy is suggesting: 'Create VEX statement with status not_affected, justification vulnerable_code_not_present'.

You can review and approve, or modify. One click and you're done."

**Show: Bulk VEX creation**

"And if you have 50 similar CVEs, you can create VEX statements for all of them at once with our bulk operation."

[Demonstrate bulk VEX with filters]

#### Demo Part 4: Reachability VEX (Ultimate Tier) (15 minutes)

**Show: Dynamic analysis submission**

"Now, for our Ultimate tier customers, we go beyond heuristics. Let me show you reachability-based VEX.

Let's say you want definitive proof that CVE-2024-5678 isn't exploitable in your app. You submit the image for dynamic analysis."

[Click "Submit for Analysis"]

"Here's what happens behind the scenes:
1. We spin up your container in an isolated sandbox
2. We run runtime profiling with eBPF to trace code execution
3. We run OWASP ZAP to fuzz web endpoints
4. We execute your custom tests (if provided)
5. We map code coverage to vulnerability locations

This takes 30-60 minutes. Let me show you a completed analysis."

[Navigate to completed analysis]

"Results:
- **CVE-2024-5678 verdict:** Code path NOT REACHED
- **Evidence:** 500 samples over 45 minutes, vulnerable function was never called
- **Additional output:** Seccomp profile (only 45 syscalls used), AppArmor profile, capability recommendations

VEXxy automatically generates a VEX statement:
- Status: `not_affected`
- Justification: `vulnerable_code_not_in_execute_path`
- Evidence: Link to full analysis report

This is empirical proof you can show auditors. No guessing."

#### Demo Part 5: Integrations & Workflows (10 minutes)

**Show: Notifications and integrations**

"VEXxy integrates into your workflow. Let me show you:

1. **Slack notifications:** When a new CRITICAL vuln is found, Slack alert goes out
2. **Jira integration:** Auto-create Jira tickets for HIGH/CRITICAL without VEX
3. **Export:** Export VEX in OpenVEX, CycloneDX, or CSAF format
4. **API access:** Everything in the UI is accessible via REST API"

[Show API docs]

#### Closing & Next Steps (5 minutes)

"That's VEXxy. Let me pause for questions."

[Q&A - see objection handling section]

"Based on what you've seen, does this address your [pain points from discovery]?"

[If yes:]
"Great! The typical next step is a 30-day proof of concept where we:
1. Connect to your scanners (Trivy/Grype)
2. Ingest your current vulnerability data
3. Train your team on VEX workflows
4. Measure impact (hours saved, false positives reduced)

We'll provide hands-on support throughout. At the end, you'll have hard data on ROI. Sound good?"

[Schedule POC kickoff]

---

## Objection Handling

### "We're already using [Competitor]"

**Listen first:** "Got it. What's working well with [Competitor]? What's not?"

**Then:**

**If Chainguard:**
"Chainguard is great if you're using their images. But VEXxy works with ANY image—your existing images, third-party images, community images. Plus, we're open source, so no vendor lock-in. Think of us as complementary: use Chainguard images where it makes sense, VEXxy for everything else."

**If Anchore/Grype:**
"Grype is an excellent scanner, and we actually integrate with it. But Grype focuses on finding vulnerabilities. VEXxy focuses on managing VEX at scale—centralization, enrichment, false positive detection. Many customers use both: Grype for scanning, VEXxy for VEX management."

**If Dependency-Track:**
"Dependency-Track is a solid OWASP project. The main differences: VEXxy is Kubernetes-native (you mentioned you're running K8s), we have deeper VEX capabilities like hierarchical scoping, and we offer reachability analysis. We're also actively developed with modern UX. Worth a side-by-side comparison?"

**If Wiz/Prisma/Orca:**
"Those are comprehensive cloud security platforms, and we're not trying to replace them. We specialize in VEX management, which they don't focus on. Many customers use Wiz for CSPM and VEXxy for VEX—we're complementary, not competitive. We can even integrate with their APIs."

### "This seems expensive"

**Clarify:** "I appreciate you being direct. Can you help me understand: compared to what?"

**Then calculate ROI:**

"Let's do some quick math:
- Your team spends [X] hours per week on false positive triage
- At $150/hour (typical loaded cost), that's $[Y] per year
- VEXxy typically reduces that by 70-90%
- So you'd save $[Z] per year
- VEXxy costs $[price], so ROI is [ratio] in Year 1

Plus, there's the compliance value: if VEX becomes a requirement and you're not ready, that's an existential risk. What's that worth?"

**Alternative:**
"We have different tiers. If [expensive tier] is out of budget, we can start with [cheaper tier] to prove value, then upgrade as you scale. Or, you can use our open-source Community Edition for free and decide later."

### "We don't have budget right now"

**Qualify:** "I understand. When does your next budget cycle open up?"

**If soon (1-3 months):**
"No problem. Let's do a POC now on the free tier, measure ROI, and when budget opens up you'll have data to justify the purchase."

**If far away (6+ months):**
"Got it. I'll check back in [month]. In the meantime, here are some resources on VEX best practices. If anything changes or you get pressure from auditors, feel free to reach out early."

**Alternative (champion building):**
"Is there any discretionary budget or a different budget line we could use? Some customers expense this as 'developer productivity' or 'compliance tools' instead of 'security tools'."

### "We'll build this internally"

**Acknowledge, then reality-check:**

"I respect that. You clearly have a strong engineering team. A few things to consider:

1. **Time to value:** Building this in-house will take 6-12 months of engineer time. VEXxy works today. What's the opportunity cost?

2. **Maintenance burden:** This isn't build-it-and-forget-it. You'll need to maintain 20+ integrations, keep up with VEX standards, handle edge cases. Is that your team's core competency?

3. **Open source option:** VEXxy's core is open source (Apache 2.0). You could fork it and customize rather than building from scratch. Why reinvent the wheel?

4. **Compliance risk:** If you need VEX for an audit in 3 months and your internal tool isn't ready, that's a risk. We derisk that.

Most teams who consider building in-house realize the ROI doesn't justify it. But if you do build, we'd love to hear feedback—maybe we can incorporate your ideas into VEXxy."

### "We need to think about it"

**Uncover the real objection:**

"Of course. Before we go, can I ask: what specifically do you need to think about? Is it:
- Technical fit? (Did something in the demo concern you?)
- Pricing? (Is it out of budget or not clear ROI?)
- Timing? (Is this not a priority right now?)
- Decision process? (Do you need input from others?)

I ask because if there's something I can address today, I'd rather clear it up now than have you thinking about it for weeks."

**If they reveal real objection:** Address it directly (see other objections)

**If they don't:**
"No problem. I'll follow up on [specific date]. If I don't hear back, I'll assume it's not a fit and won't bother you. Sound fair?"

### "Open source means no support"

**Correct the misconception:**

"Great question. Let me clarify our model:

- **Community Edition (free):** Community support via GitHub and Slack. Response times vary, but we're active.
- **Paid tiers:** Email support (48hr SLA for Professional, 24hr for Enterprise Plus, 4hr for Ultimate)
- **SaaS:** Managed infrastructure, so less support needed

Plus, with open source you have the code. If something breaks, you can debug or even fix it yourself—not possible with closed-source vendors. It's actually more reliable, not less."

### "Our security team needs to review this first"

**Facilitate, don't fight:**

"Absolutely. Security review is critical. Here's what I can provide to help:

1. **Architecture docs:** How VEXxy works, what data we access
2. **Security questionnaire:** If you have a standard questionnaire, I'll fill it out
3. **Pen test report:** [If available] Our most recent security audit
4. **Self-hosted option:** You can run VEXxy entirely on your infrastructure—we never see your data

Would it help if I joined a call with your security team to answer questions directly?"

### "We're too small / too big for this"

**If "too small":**
"I hear you. That's why we have a free tier (Community Edition). No cost, no risk. Try it, and if it saves you time, consider upgrading. If not, no harm done. You literally can't lose."

**If "too big":**
"Interesting. Why do you think that? VEXxy is built for scale—we have customers with 100+ clusters and 10,000+ images. The Ultimate tier specifically addresses enterprise-scale challenges. What scale concerns do you have?"

### "We need [feature X] that you don't have"

**Roadmap check:**
"Good feedback. [Feature X] is actually on our roadmap for [timeframe]. But let me ask: is that a deal-breaker, or could you start without it?

Many customers start with our current feature set and we add capabilities as they need them. Since we're open source, you can even contribute [feature X] if it's urgent, or we can prioritize it as part of a design partner program."

**If it's a deal-breaker:**
"I understand. Let me make sure [feature X] gets prioritized. If we can deliver it in [timeframe], would that change things?"

---

## Closing Techniques

### Trial Close (Throughout Demo)

Use mini-closes to gauge interest:
- "Does this approach make sense for your environment?"
- "Can you see your team using this?"
- "How would this change your current workflow?"

If yes → proceed. If no → pause and address concerns.

### Assumptive Close

"Great! Let me send over the contract and we can get you started next week. Do you prefer to pay by credit card or wire transfer?"

### Alternative Close

"Would you prefer to start with a 30-day POC or go straight to annual contract? POC gives you more flexibility, annual gives you 15% discount."

### Urgency Close (Use Sparingly)

"We're offering pilot pricing (50% off) to the first 10 customers, and we're at 7 now. If you'd like that pricing, we'd need to sign by [date]."

### Summary Close

"Let me recap why VEXxy makes sense for you:
1. You're spending [X hours] per week on false positives—VEXxy will cut that by 70-90%
2. You need VEX for [compliance reason]—VEXxy provides audit-ready documentation
3. You're running [Y] clusters—VEXxy centralizes all of them

Does this solve your problem? If so, let's move forward."

### Budget Close

"If budget is the only thing holding us back, let's get creative. Can you do:
- Monthly payments instead of annual?
- Start with Professional tier, upgrade to Ultimate later?
- Split across two budget lines (security + developer productivity)?"

---

## Email Templates

### Initial Outreach (Cold Email)

**Subject:** [Name], quick question about your Trivy scans at [Company]

**Body:**
Hi [Name],

I noticed [Company] is using Trivy for container scanning [source: job posting / blog post / conference talk]. Quick question: how are you managing VEX statements?

Most teams I talk to are either:
1. Not creating VEX (compliance risk)
2. Managing VEX in spreadsheets (doesn't scale)
3. Creating VEX manually per-scan (time-consuming)

**VEXxy is an open-source platform that centralizes VEX management**, works with your existing Trivy setup, and automatically detects false positives using 20+ intelligence sources.

Worth a 15-minute chat to see if it could save your team time?

[Calendar link]

Best,
[Your name]

P.S. We're open source (Apache 2.0), so you can try it without talking to sales: [GitHub link]

---

### Post-Discovery Follow-Up

**Subject:** Next steps: VEXxy demo for [Company]

**Body:**
Hi [Name],

Thanks for the great conversation today. To recap what we discussed:

**Your current state:**
- [X] Kubernetes clusters
- [Y] vulnerability alerts per month
- [Z] hours per week on triage
- Current cost: ~$[amount] per year

**Your goals:**
- Reduce false positives and alert fatigue
- Create VEX for [compliance requirement]
- Centralize data across clusters

**How VEXxy can help:**
- Reduce triage time by 70-90%
- Automate VEX creation with evidence
- Single platform for all clusters and scanners

**Next step:** Technical demo on [date/time] where I'll show you exactly how VEXxy addresses your challenges.

[Calendar link]

See you then!

Best,
[Your name]

---

### Post-Demo Follow-Up

**Subject:** VEXxy demo follow-up + POC proposal

**Body:**
Hi [Name],

Thanks for the demo today. Based on your feedback, it sounds like VEXxy's [specific feature] would really help with [specific pain point].

**Quick recap of value:**
- Save your team [X] hours per week on false positive triage
- Compliance-ready VEX documentation for [requirement]
- Empirical proof of non-exploitability (Ultimate tier)

**Proposed next step:**
30-day proof of concept where we:
1. Connect to your Trivy/Grype scanners
2. Ingest and enrich your current vulnerability data
3. Train your team on VEX workflows
4. Measure ROI (time saved, alerts reduced)

**Pricing:** [Tier] at $[price]/year, or 50% off for POC pilot

Can we schedule a kickoff call for next week?

[Calendar link]

Best,
[Your name]

---

### POC Kickoff Email

**Subject:** VEXxy POC kickoff: action items

**Body:**
Hi [Name],

Excited to get started with your VEXxy POC! Here's what we need from you:

**Pre-POC setup (by [date]):**
- [ ] Docker/Kubernetes access (to deploy VEXxy)
- [ ] Scanner access (Trivy/Grype API endpoints or scan outputs)
- [ ] 2-3 team members for training (1 hour)

**Week 1: Setup & Training**
- Deploy VEXxy in your environment
- Connect scanners and ingest initial data
- Training session for your team

**Weeks 2-4: Usage & Measurement**
- Your team uses VEXxy for vulnerability triage
- We measure: time saved, false positives detected, VEX statements created
- Weekly check-in calls (30 min)

**End of POC: Results Review**
- ROI analysis and decision

Sound good? Let me know if you have any questions!

Best,
[Your name]

---

### Closing Email (After POC)

**Subject:** VEXxy POC results + next steps

**Body:**
Hi [Name],

Great working with your team over the past 30 days! Here are the results:

**POC Metrics:**
- Vulnerabilities analyzed: [X]
- False positives detected: [Y] ([Z]% reduction)
- VEX statements created: [N]
- Time saved: [M] hours per week

**Value delivered:**
- $[amount] per year in analyst time savings
- Compliance-ready VEX documentation
- Team feedback: [quote from champion]

**Next step:**
Convert to annual subscription. With pilot pricing (50% off), that's $[discounted price] for Year 1.

Contract attached. Let me know if you have any questions!

Best,
[Your name]

---

## Pricing & Negotiation

### Negotiation Principles

1. **Anchor high:** Always start with list price, discount from there
2. **Trade, don't give:** "I can do that discount if you sign by Friday"
3. **Bundle:** "If you commit to 2 years, I can include Ultimate tier upgrades"
4. **Never discount >30%:** It cheapens the brand and sets bad precedent

### Common Negotiation Scenarios

**They ask for 50% discount:**
"I can't do 50%, but I can do:
- 15% discount for annual prepay (vs. monthly)
- 20% discount if you sign this quarter
- 25% discount for 2-year commitment
- Or we can start with a lower tier and upgrade later?"

**They want to pay monthly:**
"Monthly is available for SaaS at $[price/mo]. Self-hosted is annual only, but we can do quarterly payments if that helps with cash flow."

**They want free pilot:**
"I can't do free, but I can do:
- 50% discount on first 6 months (pilot pricing)
- 30-day money-back guarantee
- Or use our open-source Community Edition free, then upgrade"

**They want more features in lower tier:**
"I hear you. The tier structure is pretty firm—Professional includes [X, Y], Enterprise Plus includes [A, B]. But if you commit to Enterprise Plus for Year 2, I can give you [one extra feature] in Year 1 at Professional pricing."

---

## Champion Building

### Identifying Champions

**Characteristics of a good champion:**
- ✅ Has personal pain (frustrated with current process)
- ✅ Has credibility in organization (people listen to them)
- ✅ Has access to economic buyer (can get you in the room)
- ✅ Has time and motivation (not distracted by other priorities)
- ✅ Benefits from success (career advancement, team morale, etc.)

**How to find them:**
- Look for the person who asks the most questions in demos
- Look for the person who says "We need this" in meetings
- Look for the person who follows up proactively

### Developing Champions

**1. Give them ammunition:**
- One-pagers they can share internally
- ROI calculator
- Competitive comparison
- Customer case studies

**2. Make them the hero:**
- Position VEXxy as *their* solution
- Give them credit for finding it
- Ask for their input on POC success criteria

**3. Coach them on selling internally:**
- "What objections do you expect from [stakeholder]?"
- "How can I help you address those?"
- "Do you need me on the call, or would you prefer to present alone?"

**4. Build relationship beyond the deal:**
- Invite to beta features
- Ask for product feedback
- Connect on LinkedIn
- Offer to be a reference for their promotion/new job

---

## Success Metrics for Sales

**Track these metrics:**
- Conversion rate: Demo → POC → Close
- Average deal size (by tier)
- Sales cycle length (days from first touch to close)
- Win/loss ratio
- Reasons for loss (objections that didn't get handled)

**Continuous improvement:**
- Record sales calls (with permission)
- Review losses with team
- A/B test pitch variations
- Share wins and learnings

---

**Document Owner:** Sales Team
**Last Updated:** November 2025
**Next Review:** Quarterly (adjust based on real-world feedback)
