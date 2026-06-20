# IdentityLens AI — Presentation

> Use this document as slide content. Each `---` separator represents one slide.
> Recommended: 10–12 slides, ~5 minute pitch + 3 minute demo.

---

## SLIDE 1 — Title

# IdentityLens AI
### Cross-Platform Identity Risk Intelligence

**See every identity. Rank every risk. Quantify every breach.**

Team: [Your Team Name]
Event: [Hackathon Name]

---

## SLIDE 2 — The Problem

# Identity Is the #1 Attack Vector

- **81% of breaches** involve stolen or misused credentials
- Enterprises use **6+ identity systems** — AD, AWS, Azure, Okta, Salesforce, ServiceNow
- Each system shows a **different piece** of the same person
- Security teams have **no unified view** of who can cause the most damage

> "We know we have risky accounts. We just don't know which ones matter most."

---

## SLIDE 3 — Three Gaps We Identified

# The Three Blind Spots

| Gap | Impact |
|-----|--------|
| **Fragmented visibility** | Admin in AWS, dormant in AD — never connected |
| **No prioritization** | Everything flagged "high" — nothing gets fixed |
| **No business context** | Reports say "Domain Admin" — executives need "2.4M records at risk" |

Traditional IAM tools manage accounts. **Nobody ranks identities by real-world damage potential.**

---

## SLIDE 4 — Our Solution

# IdentityLens AI

A unified identity risk intelligence platform that:

1. **Resolves** identities across 6 platforms into one person
2. **Scores** every identity 0–100 with explainable risk factors
3. **Detects** behavioral anomalies with machine learning
4. **Maps** attack paths from identity to sensitive data
5. **Quantifies** blast radius in records exposed
6. **Recommends** specific remediation actions
7. **Maps** findings to NIST, MITRE, GDPR, and CIS compliance

---

## SLIDE 5 — How It Works

# Architecture at a Glance

```
6 Platforms → Identity Resolution → Unified Identity
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
              Risk Scoring        ML Anomaly           Graph Engine
              (7 dimensions)     (Isolation Forest)   (Attack Paths)
                    │                   │                   │
                    └───────────────────┼───────────────────┘
                                        ▼
                              Identity 360° Briefing
                         (Score + Impact + Actions)
```

**350 identities · 1,500+ audit events · Real-time pipeline**

---

## SLIDE 6 — Risk Scoring Engine

# Explainable Risk Scoring (0–100)

Seven dimensions, each with clear triggers:

- **Privilege Risk** — How many admin-level access across platforms?
- **Dormancy Risk** — Admin account inactive for 124+ days?
- **Token Risk** — API key never rotated in 421 days?
- **Offboarding Risk** — Terminated but still active?
- **Behavior Risk** — MFA disabled? Failed logins? Unusual geo?
- **Escalation Risk** — Recent privilege escalation?
- **Platform Spread** — Access across 6 systems?

Every score comes with **human-readable reasons**, not a black box.

---

## SLIDE 7 — Machine Learning Layer

# ML Anomaly Detection

**Algorithm:** Isolation Forest (Scikit-learn)

Flags the ~8% most unusual identities based on:

- Login patterns and frequency
- Privilege change velocity
- Cross-platform spread
- Token usage anomalies
- Geographic and temporal outliers

Each anomaly includes an **explainable feature breakdown** — which behaviors triggered the flag and why.

---

## SLIDE 8 — Identity 360° Hero Screen

# The Identity 360° Briefing

**Demo: Yatin Sangwan — Risk 98/100**

| Finding | Detail |
|---------|--------|
| Privileges | Domain Admin (AD) · AWS Admin · Global Admin (Azure) |
| Token | 421-day-old API key, never rotated |
| Dormancy | Inactive 124 days with admin access |
| Access | Customer Database · Production S3 · HR Systems |
| Blast Radius | **2.4 million records** |
| Attack Path | AWS Admin → Production S3 → Customer Data |
| MITRE | T1078 Valid Accounts · T1098 Account Manipulation |

**Recommended:** Remove AWS Admin · Rotate Token · Disable Dormant Access

---

## SLIDE 9 — Dual Audience Design

# Built for Two Audiences

### Technical View (Engineers & SOC)
- Interactive identity graph
- Effective permissions with inheritance paths
- 90-day audit log timeline
- AI copilot analysis
- One-click remediation approval

### Executive View (CISO & Board)
- 14 high-risk identities
- 4.8M records at potential exposure
- 9 dormant admins · 22 offboarding gaps
- 5 critical findings requiring immediate action

**One platform. Two lenses. Zero confusion.**

---

## SLIDE 10 — Compliance & Incidents

# Beyond Risk Scoring

**Auto-Generated Incidents**
- Critical incidents created for identities scoring ≥85
- Linked to compliance controls and remediation actions
- SOC-ready triage workflow

**Compliance Mapping**
- NIST SP 800-53 (AC-2, AC-6)
- MITRE ATT&CK (T1078, T1098, T1552)
- GDPR (Articles 5, 32)
- CIS Controls (5, 6)

Audit-ready reporting generated automatically from risk findings.

---

## SLIDE 11 — Live Demo Flow

# Demo Walkthrough (3 minutes)

1. **Dashboard** — Org-wide risk KPIs and trends
2. **Leaderboard** — Top 20 ranked identities
3. **Click Yatin Sangwan** — Identity 360° hero briefing
4. **Attack path** — AWS Admin → 2.4M records
5. **Toggle views** — Technical depth vs. Executive clarity
6. **Incidents** — Auto-generated, compliance-linked
7. **Graph Explorer** — Interactive attack surface map

**Login:** admin / admin123

---

## SLIDE 12 — Impact & What's Next

# Why IdentityLens Wins

| Today (Manual) | With IdentityLens |
|----------------|-------------------|
| Weeks of audit work | Seconds to rank 350 identities |
| Siloed per-platform views | Unified cross-platform identity |
| "Investigate further" | "Remove AWS Admin, rotate token" |
| Permission jargon | "2.4M records exposed" |
| No compliance mapping | NIST + MITRE + GDPR auto-mapped |

### What's Next
- Live connector integrations (Okta API, AWS IAM, Azure AD Graph)
- Automated remediation execution (not just recommendations)
- Real-time streaming audit ingestion
- SSO and enterprise RBAC

---

## SLIDE 13 — Closing

# IdentityLens AI

**The question isn't "do we have risky accounts?"**

**It's "which account could destroy us tomorrow — and what do we do about it?"**

IdentityLens answers that question in seconds.

---

### Thank you.

**Questions?**

Demo: http://localhost:3000
Docs: `/docs/JUDGE_GUIDE.txt`
