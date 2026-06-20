# IdentityLens AI — Technical Documentation

## 1. Overview

IdentityLens AI is a cross-platform identity risk intelligence platform that unifies identity data from six enterprise systems, computes explainable risk scores, detects behavioral anomalies with machine learning, maps attack paths through a privilege graph, and delivers remediation guidance aligned with compliance frameworks.

**Scope:** 350 unified identities, 1,500+ audit events, nested group memberships, API tokens, offboarding records, and auto-generated incidents.

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Frontend (Next.js 14)                       │
│  Dashboard │ Leaderboard │ Identity 360° │ Incidents │ Graph   │
└────────────────────────────┬────────────────────────────────────┘
                             │ REST / JSON (JWT)
┌────────────────────────────▼────────────────────────────────────┐
│                     Backend (FastAPI)                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │ Auth (JWT)   │  │ API Routers  │  │ Intelligence Pipeline  │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Services Layer                                              ││
│  │ Resolution │ Privileges │ Risk │ ML │ Graph │ Remediation   ││
│  │ Compliance │ Impact Analysis │ Data Quality │ AI Copilot   ││
│  └─────────────────────────────────────────────────────────────┘│
└────────────────────────────┬────────────────────────────────────┘
                             │ SQLAlchemy ORM
┌────────────────────────────▼────────────────────────────────────┐
│              PostgreSQL (production) / SQLite (local)           │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Breakdown

| Layer | Technology | Responsibility |
|-------|-----------|----------------|
| Frontend | Next.js 14, TypeScript, TailwindCSS | SPA with server-side rendering; charts (Recharts), graph viz (React Flow) |
| Backend | FastAPI, Uvicorn, Pydantic | REST API, auth, business logic, pipeline orchestration |
| Database | PostgreSQL / SQLite | Persistent storage for identities, audit logs, incidents, tokens |
| Analytics | Pandas, NumPy, NetworkX, Scikit-learn | Risk computation, graph analysis, ML anomaly detection |
| Deployment | Docker Compose | Multi-container orchestration (db + backend + frontend) |

### 2.3 Data Model

Core entities stored in the database:

| Entity | Purpose |
|--------|---------|
| `UnifiedIdentity` | Resolved person with risk score, privileges, remediation actions, compliance mappings |
| `IdentitySnapshot` | Raw platform account snapshot (username, privilege, last login, status) |
| `GroupMembership` | Group assignments with nested parent-group inheritance |
| `AuditLog` | Platform audit events (login, MFA disabled, role escalation, failed auth) |
| `ApiToken` | API token metadata (age, rotation status, permissions) |
| `OffboardingRecord` | HR offboarding status vs. active platform accounts |
| `Incident` | Auto-generated security incidents for high-risk identities |
| `AppUser` | Platform login users (admin, analyst roles) |

### 2.4 Intelligence Pipeline

On bootstrap and on-demand (`POST /api/pipeline/run`), the pipeline executes sequentially:

1. **Data generation** — 350 identities with cross-platform accounts, groups, tokens, audit events
2. **Identity resolution** — correlate snapshots to unified identities via employee ID and email
3. **Privilege calculation** — traverse nested group hierarchies to compute effective privileges
4. **Risk scoring** — explainable 0–100 score across 7 dimensions
5. **ML anomaly detection** — Isolation Forest on 8 behavioral features
6. **Remediation generation** — prioritized platform-specific actions
7. **Compliance mapping** — NIST, MITRE ATT&CK, GDPR, CIS Controls
8. **Graph construction** — NetworkX directed graph of identity relationships
9. **Impact analysis** — blast radius, attack chain, hero briefing for Identity 360°

---

## 3. Analysis Algorithms

### 3.1 Identity Resolution

**File:** `backend/app/services/identity_resolution.py`

Correlates platform-specific account snapshots into unified identities using:

- **Primary key:** `employee_id` (e.g., `EMP10000`)
- **Secondary key:** email address (for Okta and cross-platform matching)
- **Output:** One `UnifiedIdentity` per person with a map of platform accounts (username, privilege level, last login, account status)

### 3.2 Effective Privilege Calculation

**File:** `backend/app/services/privilege_calculator.py`

Computes the true privilege level by traversing nested group membership chains:

1. Start with the user's direct privilege assignment on each platform
2. Collect all groups the user belongs to
3. Recursively traverse `parent_group` links (e.g., Enterprise Admins → Domain Admins → Helpdesk)
4. Collect privilege levels from every group in the inheritance chain
5. **Effective privilege = maximum rank** in the privilege hierarchy

**Privilege hierarchy (rank order):**

```
Standard User (1) → Power User (2) → Read Only Admin (3) → Helpdesk Admin (4)
→ Cloud Admin (5) → Security Admin (6) → AdministratorAccess (7)
→ Global Admin (8) → Domain Admin (9) → Super Admin (10)
```

This ensures that a user assigned "Power User" directly but inheriting "Domain Admin" through group nesting is correctly scored as Domain Admin.

### 3.3 Explainable Risk Scoring

**File:** `backend/app/services/risk_scoring.py`

Produces a **0–100 risk score** with a breakdown across seven dimensions:

| Dimension | Max Points | Trigger |
|-----------|-----------|---------|
| Privilege Risk | 35 | Count and severity of high privileges across platforms |
| Platform Spread | 20 | Number of platforms the identity has access to |
| Dormancy Risk | 25 | High-privilege account inactive >90 days |
| Offboarding Risk | 30 | Terminated employee with active platform accounts |
| Token Risk | 20 | API tokens aged >180 days or never rotated |
| Behavior Risk | 20 | Suspicious audit events (MFA disabled, failed auth, Tor exit nodes) |
| Escalation Risk | 15 | Recent privilege escalation events |

Each contributing factor is recorded as a human-readable string in `risk_factors` (e.g., "Dormant 124 days", "Unrotated token aged 421 days").

**Anchor identity floor:** Yatin Sangwan (`EMP10000`) has a minimum risk score of 98 to serve as the demo anchor.

### 3.4 Machine Learning — Isolation Forest Anomaly Detection

**File:** `backend/app/services/ml_anomaly.py`

| Parameter | Value |
|-----------|-------|
| Algorithm | Isolation Forest (Scikit-learn) |
| Contamination | 0.08 (8% flagged as anomalous) |
| Estimators | 100 |
| Scaling | StandardScaler on all features |

**Feature vector (8 dimensions per identity):**

1. Login frequency (30-day audit events)
2. Privilege change count
3. Platform count
4. Token count
5. Failed authentication count
6. Hour-of-day variance (unusual login times)
7. Geo-location diversity
8. Dormancy days (max across admin accounts)

Anomalies receive an `anomaly_score` and an explainable breakdown via `explain_anomaly()`, identifying which features contributed most to the flag.

### 3.5 Graph Engine & Attack Path Analysis

**File:** `backend/app/services/graph_engine.py`

Builds a **directed graph** (NetworkX `DiGraph`) with the following node types and relationships:

```
User ──HasAccount──→ Platform ──HasRole──→ Role ──HasAccess──→ Resource
  │                      │
  └──MemberOf──→ Group ──┘        Token ──HasAccess──→ Resource
  └──OwnsToken──→ Token
```

**Attack path discovery:** Uses `nx.all_simple_paths()` with a cutoff of 6 hops from the user node to critical resource nodes (Customer Database, Production S3, Azure Key Vault, etc.). Returns up to 5 paths with labeled node sequences.

**Visualization:** Subgraph extraction via BFS from the target identity, capped at 60 nodes, exported as React Flow nodes/edges for the frontend graph viewer.

### 3.6 Impact Analysis & Hero Briefing

**File:** `backend/app/services/impact_analysis.py`

Generates the Identity 360° hero briefing displayed on the profile page:

| Output | Method |
|--------|--------|
| Critical privileges | Direct platform account privileges for AD, AWS, Azure |
| Accessible resources | Match effective privileges against a resource catalog |
| Blast radius | Maximum records exposed across accessible resources |
| Attack chain | Narrative path: AWS Admin → Production S3 → Customer Data → N records |
| MITRE tags | T1078 (Valid Accounts) + T1098 (Account Manipulation) for dormant/privileged identities |
| Recommended actions | Contextual remediation (Remove AWS Admin, Rotate Token, Disable Dormant Access) |
| Executive context | Org-wide CISO metrics (high-risk count, data exposure, dormant admins, offboarding gaps, critical findings) |

**Resource catalog:**

| Resource | Records | Required Privileges |
|----------|---------|-------------------|
| Customer Database | 2,400,000 | AdministratorAccess, Domain Admin, Global Admin, Super Admin |
| Production S3 | 800,000 | AdministratorAccess, Cloud Admin, Super Admin |
| HR Systems | 150,000 | Domain Admin, Super Admin, Security Admin |
| Azure Key Vault | 50,000 | Global Admin, Security Admin, Cloud Admin |
| Identity Provider | 12,000 | Security Admin, Super Admin, Global Admin |

### 3.7 Compliance Mapping

**File:** `backend/app/services/compliance.py`

Maps risk breakdown dimensions to regulatory frameworks:

| Framework | Controls Mapped |
|-----------|----------------|
| NIST SP 800-53 | AC-2 (Account Management), AC-6 (Least Privilege) |
| MITRE ATT&CK | T1078 (Valid Accounts), T1098 (Account Manipulation), T1552 (Unsecured Credentials) |
| GDPR | Article 32 (Security of Processing), Article 5 (Data Minimization) |
| CIS Controls | CIS 5 (Account Management), CIS 6 (Access Control Management) |

### 3.8 AI Copilot Analysis

**File:** `backend/app/services/remediation.py`

Generates structured AI analysis for each identity:

- **Root causes:** Human-readable explanations of why the identity is risky
- **Attack narrative:** Step-by-step description of how an attacker could exploit the identity
- **Remediation actions:** Prioritized, platform-specific fixes with severity levels
- **Optional OpenAI integration:** Falls back to the built-in intelligence engine when no API key is configured

---

## 4. User Interface Design

### 4.1 Design Principles

- **Dual audience:** Engineers need depth (graphs, permissions, logs); executives need clarity (KPIs, blast radius, recommended actions)
- **Quantified risk:** Every finding includes a number — records exposed, days dormant, token age
- **Progressive disclosure:** Hero briefing first, then toggle between Executive and Technical views
- **Dark theme:** Security operations center aesthetic with color-coded risk severity

### 4.2 Color System

| Risk Level | Score Range | Color |
|-----------|-------------|-------|
| Critical | 80–100 | Red |
| High | 60–79 | Orange |
| Medium | 40–59 | Yellow |
| Low | 0–39 | Green |

### 4.3 Page Inventory

| Page | Route | Purpose |
|------|-------|---------|
| Login | `/login` | JWT authentication (admin/analyst demo accounts) |
| Executive Dashboard | `/` | KPI cards, risk trend charts, department breakdown, privilege heatmap, access matrix, security event timeline, top-10 leaderboard preview |
| Risk Leaderboard | `/leaderboard` | Searchable, sortable top-20 identity rankings with click-through to Identity 360° |
| Identity 360° | `/identities/{id}` | Hero briefing + Executive/Technical view toggle |
| Incident Center | `/incidents` | Auto-generated incidents with severity, status, and compliance controls |
| Incident Detail | `/incidents/{id}` | Full incident findings and linked identity |
| Compliance | `/compliance` | Org compliance score, framework summaries, per-identity control findings |
| Attack Path Explorer | `/graph` | Global interactive identity graph with node/edge statistics |

### 4.4 Identity 360° — Hero Screen Layout

The hero screen is the platform's centerpiece, designed for judge demos:

```
┌─────────────────────────────────────────────────────────────────┐
│  ⚠ CRITICAL IDENTITY                    Risk Score: 98/100     │
│  Yatin Sangwan · Security Analyst · IT Security · EMP10000     │
├──────────────────┬──────────────────┬───────────────────────────┤
│ Elevated Privs   │ Access To        │ MITRE ATT&CK              │
│ • Domain Admin   │ → Customer DB    │ T1078 Valid Accounts      │
│ • AWS Admin      │ → Production S3  │ T1098 Account Manipulation│
│ • Global Admin   │ → HR Systems     │                           │
│                  │                  │ Recommended Actions       │
│ 🔑 421-day token │ Blast Radius:    │ ✓ Remove AWS Admin        │
│ ⚡ 124-day dormant│ 2.4M records    │ ✓ Rotate Token            │
│                  │                  │ ✓ Disable Dormant Access  │
├──────────────────┴──────────────────┴───────────────────────────┤
│ Attack Path: AWS Admin → Production S3 → Customer Data → 2.4M  │
│ Potential Impact: 2.4M records exposed                          │
└─────────────────────────────────────────────────────────────────┘
│  [Technical View]  [Executive View]                              │
├─────────────────────────────────────────────────────────────────┤
│ Technical: Graph │ Permissions │ Audit Logs │ AI │ Remediation  │
│ Executive: Org KPIs │ AI Summary │ Risk Factors                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.5 View Toggle Behavior

| View | Audience | Content |
|------|----------|---------|
| **Technical View** (default) | Engineers, SOC analysts | Identity graph, effective permissions with inheritance paths, 90-day audit timeline, API tokens, AI copilot analysis, risk breakdown bars, remediation queue with approve action |
| **Executive View** | CISO, board | Org-wide metrics (14 high-risk identities, 4.8M records exposure, 9 dormant admins, 22 offboarding gaps, 5 critical findings), AI risk summary, top risk factors |

### 4.6 Navigation

Persistent sidebar with icons:
- Executive Dashboard
- Risk Leaderboard
- Incident Center
- Compliance
- Attack Path Explorer

### 4.7 Responsive Design

- Grid layouts adapt from single-column (mobile) to multi-column (desktop)
- Hero briefing uses a 3-column grid on large screens, stacking on smaller viewports
- Graph viewer has configurable height with pan/zoom controls and minimap

---

## 5. API Reference (Key Endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Authenticate and receive JWT token |
| GET | `/api/dashboard/kpis` | Executive dashboard KPI metrics |
| GET | `/api/dashboard/leaderboard` | Ranked identity list with search/sort |
| GET | `/api/identities/{id}` | Full Identity 360° profile with hero briefing |
| PATCH | `/api/identities/{id}/remediation/{action_id}` | Approve remediation action |
| GET | `/api/incidents` | List all incidents |
| PATCH | `/api/incidents/{id}` | Update incident status |
| GET | `/api/compliance/report` | Organization compliance report |
| GET | `/api/graph/global` | Global identity graph for explorer |
| POST | `/api/pipeline/run` | Trigger full intelligence recomputation |
| GET | `/api/pipeline/status` | Pipeline run status and data quality |

---

## 6. Deployment

### Local Development

```bash
# Backend
cd backend && source venv/bin/activate
DATABASE_URL=sqlite:///./identitylens.db uvicorn app.main:app --port 8000

# Frontend
cd frontend && npm run build
NEXT_PUBLIC_API_URL=http://localhost:8000/api npm run start -p 3000
```

### Docker

```bash
docker compose up --build
```

Services: PostgreSQL (5432), Backend (8000), Frontend (3000).

### Demo Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Administrator |
| analyst | analyst123 | Analyst |

---

## 7. Demo Anchor Identity

| Field | Value |
|-------|-------|
| Name | Yatin Sangwan |
| Employee ID | EMP10000 |
| Unified ID | UID-EMP10000 |
| Department | IT Security |
| Role | Security Analyst |
| Risk Score | 98/100 |
| Platforms | All 6 (AD, AWS, Azure, Okta, Salesforce, ServiceNow) |
| Key Findings | Domain Admin + AWS AdministratorAccess + Global Admin, 421-day token, 124-day dormancy |
| Blast Radius | 2.4M customer records |
| Direct URL | `/identities/UID-EMP10000` |
