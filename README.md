# IdentityLens AI

Cross-Platform Identity Risk Intelligence Platform — an enterprise-grade AI-powered Identity Governance and Privileged Access Intelligence system.

> Société Générale Hackathon 2027 · RVCE

## About

IdentityLens AI is a cross-platform identity risk intelligence platform built to answer the question every security team struggles with: **who in our organization can cause the most damage if their account is compromised?**

Modern enterprises manage identities across fragmented systems—Active Directory, AWS IAM, Azure AD, Okta, Salesforce, and ServiceNow—each showing a different slice of the same person. A user may appear low-risk in one tool while holding dormant admin access, unrotated API tokens, and cross-cloud privileges elsewhere. Traditional IAM dashboards manage accounts; they do not rank identities by real-world damage potential. IdentityLens closes that gap.

The platform unifies siloed identity data into a single view per person, scores every identity from 0 to 100 with explainable risk factors, and quantifies impact in **records exposed**—not just permission names. It correlates 350 enterprise identities and 1,500+ audit events, resolves accounts across six platforms via employee ID and email matching, and computes **effective privileges** by traversing nested group inheritance chains.

At the core is a multi-engine intelligence pipeline. An explainable risk engine evaluates seven dimensions: privilege concentration, dormancy, offboarding gaps, token age, suspicious behavior, privilege escalation, and platform spread. **Isolation Forest** machine learning flags anomalous identities with feature-level explanations. A **NetworkX graph engine** maps attack paths from users through roles and groups to sensitive resources such as customer databases and production storage. Findings are automatically mapped to **NIST, MITRE ATT&CK, GDPR, and CIS Controls**, with prioritized remediation actions generated for each identity.

The centerpiece is **Identity 360°**—a hero briefing that surfaces critical privileges, blast radius, MITRE tags, attack chains, and recommended fixes in one screen. Dual **Executive** and **Technical** views serve CISOs with org-wide exposure metrics and engineers with interactive graphs, permission inheritance paths, and audit timelines. Auto-generated incidents and an AI security copilot complete the workflow from detection to action.

Built with **FastAPI**, **Next.js 14**, **PostgreSQL**, **NetworkX**, and **Scikit-learn**. Deploy locally with Docker Compose or SQLite in minutes. Open the Risk Leaderboard, click **Yatin Sangwan (98/100)**, and watch a dormant admin account connect to 2.4 million exposed records in seconds.

**Demo credentials:** `admin` / `admin123` · Full documentation in `/docs/`

## Overview

IdentityLens AI discovers hidden identity risks across hybrid environments by correlating identities from Active Directory, AWS IAM, Azure AD, Okta, Salesforce, and ServiceNow into a unified view.

Unlike traditional IAM dashboards, it reveals cross-platform risks:

- Who has the highest **effective privileges** (including nested group inheritance)
- Which terminated employees still have **active accounts**
- Which service accounts and API tokens create **attack paths**
- Which identities are **anomalous** (Isolation Forest ML)
- What **remediation actions** security teams should take

## Architecture

```
┌─────────────────┐     ┌──────────────────────────────────────────┐
│  Next.js UI     │────▶│  FastAPI Backend                         │
│  Dashboard      │     │  ├── Identity Resolution Engine          │
│  Leaderboard    │     │  ├── Effective Privilege Calculator      │
│  Identity 360°  │     │  ├── NetworkX Graph Engine               │
│  Incidents      │     │  ├── Risk Scoring Engine                 │
│  Compliance     │     │  ├── Isolation Forest Anomaly Detection  │
└─────────────────┘     │  ├── AI Security Copilot                 │
                          │  └── Remediation + Compliance Mapping    │
                          └──────────────┬───────────────────────────┘
                                         │
                                  ┌──────▼──────┐
                                  │ PostgreSQL  │
                                  └─────────────┘
```

## Quick Start (Docker)

```bash
docker compose up --build
```

| Service  | URL                          |
|----------|------------------------------|
| Frontend | http://localhost:3000        |
| Backend  | http://localhost:8000/docs   |
| API      | http://localhost:8000/api    |

**Demo credentials:** `admin` / `admin123` or `analyst` / `analyst123`

## Local Development

### Backend

```bash
cd backend
python3.11 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# SQLite (no Docker required)
export DATABASE_URL=sqlite:///./identitylens.db
uvicorn app.main:app --reload --port 8000
```

Or use the convenience script from the repo root:

```bash
chmod +x start-dev.sh && ./start-dev.sh
```

### Frontend

```bash
cd frontend
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000/api npm run dev
```

## Features

### Data Layer
- **350 simulated identities** across 6 platforms
- **1,500+ audit log events** (login, privilege change, MFA disabled, role escalation, etc.)
- Group membership with **nested inheritance**
- Offboarding records and API token inventory

### Intelligence Engines
| Engine | Description |
|--------|-------------|
| Identity Resolution | Correlates AD/Okta/AWS accounts to unified identities via employee_id + email |
| Privilege Calculator | Traverses nested groups to compute effective privileges |
| Graph Engine | NetworkX-powered attack path analysis with React Flow visualization |
| Risk Scoring | Explainable 0–100 score across 7 risk dimensions |
| ML Anomaly Detection | Isolation Forest on login frequency, geo diversity, privilege changes |
| AI Copilot | Human-readable risk summaries with remediation guidance |
| Compliance | Maps findings to NIST AC-2/AC-6, MITRE ATT&CK, GDPR, CIS Controls |

### UI Screens
- **Executive Dashboard** — KPIs, risk distribution, department heatmap, privilege matrix
- **Risk Leaderboard** — Top 20 searchable/sortable risky identities
- **Identity 360° Profile** — Full privilege inventory, attack paths, tokens, timeline, AI analysis
- **Incident Center** — Clustered critical alerts with investigation view
- **Compliance Module** — Automated framework mapping and reports
- **Attack Path Explorer** — Interactive identity graph

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/login` | JWT authentication |
| GET | `/api/dashboard/kpis` | Executive KPIs |
| GET | `/api/dashboard/leaderboard` | Risk leaderboard |
| GET | `/api/identities/{id}` | Identity 360° profile |
| GET | `/api/incidents` | Incident list |
| GET | `/api/compliance/report` | Compliance report |
| GET | `/api/graph/global` | Global identity graph |

## Tech Stack

- **Frontend:** Next.js 14, TypeScript, TailwindCSS, ShadCN, Recharts, React Flow
- **Backend:** FastAPI, SQLAlchemy, PostgreSQL
- **Analytics:** Pandas, NumPy, NetworkX, Scikit-Learn
- **Auth:** JWT + RBAC
- **Deployment:** Docker Compose

## Optional: OpenAI Integration

Set environment variables on the backend:

```bash
USE_OPENAI=true
OPENAI_API_KEY=sk-...
```

This enables LLM-powered risk summaries on the Identity 360° profile.
