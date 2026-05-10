# NORDA Bank MAS — Architecture Document

**Project:** Trust in the Age of Autonomous AI  
**Challenge:** HACK'N'BIZ · Fortum Junior Entreprise · May 2026  
**Domain:** Fraud Detection & Investigation  

---

## 1. System Overview

NORDA MAS is a multi-agent fraud detection system built for NORDA Bank. Every transaction entering the pipeline is simultaneously evaluated by two specialized AI agents, validated by an independent governance layer, and made available for human operator review — all before any decision is executed.

**Core design principle:** No agent decision reaches production without cryptographic validation, an immutable audit trail, and a human override path.

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NORDA MAS PLATFORM                          │
│                                                                     │
│  ┌──────────────┐    POST /events/inject                            │
│  │  Transaction  │──────────────────────────────────────────────┐   │
│  │  Simulator    │                                              │   │
│  └──────────────┘                                              │   │
│                                                                │   │
│                         ┌─────────────────────────────────┐   │   │
│                         │    ORCHESTRATOR  (FastAPI)       │◄──┘   │
│                         │  • JWT-signs every outgoing msg  │       │
│                         │  • WebSocket broadcast to UI     │       │
│                         │  • HITL REST API                 │       │
│                         │  • Transaction cache             │       │
│                         │  • MITRE ATLAS tracker           │       │
│                         └────────────┬────────────────────┘       │
│                                      │ Redis Streams (JWT-signed)  │
│               ┌──────────────────────┼──────────────────┐         │
│               │ norda:events         │ detection:input  │ comp:in  │
│               ▼                      ▼                  ▼         │
│  ┌────────────────────┐  ┌──────────────────┐  ┌──────────────┐   │
│  │   GOVERNANCE        │  │ DETECTION AGENT  │  │  COMPLIANCE  │   │
│  │   LAYER             │  │                  │  │  AGENT       │   │
│  │ • JWT verification  │  │ • FATF/OFAC risk │  │ • Sanctions  │   │
│  │ • Injection guard   │  │ • Velocity check │  │   screening  │   │
│  │ • SHA256 chain      │  │ • Amount thresh  │  │ • PEP detect │   │
│  │ • HMAC signature    │  │ • Score 0.0–1.0  │  │ • AML types  │   │
│  │ • Wazuh bridge      │  │ • HITL if ≥ 0.7  │  │ • HITL if    │   │
│  └────────┬───────────┘  └────────┬─────────┘  │  sanctions   │   │
│           │                       │             └──────┬───────┘   │
│           │ norda:decisions        │ norda:events       │           │
│           ▼                       └────────────────────┘           │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │                    PostgreSQL                             │      │
│  │              Signed Audit Chain                          │      │
│  │  seq | agent_id | input_hash | entry_hash | prev_hash    │      │
│  │       | signature | decision | rationale | timestamp      │      │
│  └──────────────────────────┬───────────────────────────────┘      │
│                             │ WebSocket broadcast                   │
│                             ▼                                       │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │              REACT OPERATOR DASHBOARD  :3000              │      │
│  │  Live Agent Feed │ HITL Queue │ ATLAS Panel │ Audit Log   │      │
│  │  Network Graph   │           │ Red Team    │             │      │
│  └──────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Responsibilities

### 3.1 Detection Agent
- **Purpose:** Real-time transaction risk scoring
- **Input:** Raw transaction payload via `norda:detection-agent:input` Redis Stream
- **Logic:** Rule-based weighted scoring across 6 risk dimensions (country, amount, velocity, merchant category, transaction type, jurisdiction combination)
- **Output:** `risk_score` (0.0–1.0), `risk_tier` (LOW/MEDIUM/HIGH/CRITICAL), `flags[]`, `rationale`
- **HITL trigger:** `risk_score ≥ 0.7`
- **ATLAS mapping:** AML0015 — Evade ML Model (monitored)

### 3.2 Compliance Agent
- **Purpose:** AML/sanctions/PEP screening
- **Input:** Raw transaction payload via `norda:compliance-agent:input` Redis Stream
- **Logic:** OFAC SDN list screening, EU Consolidated Sanctions, simulated PEP account detection, AML typology pattern matching (structuring, sanctions evasion via crypto, high-risk sector large amounts)
- **Output:** `sanctions_hit`, `pep_hit`, `aml_flags[]`, `kyc_status` (CLEAR/REVIEW_REQUIRED/ENHANCED_DUE_DILIGENCE/BLOCKED), `rationale`
- **HITL trigger:** `sanctions_hit OR pep_hit`
- **Regulation:** AML 6th Directive Art. 18, GDPR, MiFID II Art. 25

### 3.3 Governance Layer
- **Purpose:** Independent validation of every agent decision before it enters the audit chain
- **Trust model:** Agents are untrusted by default. Governance verifies the JWT signature on every message before processing.
- **Injection guard:** Scans all string values in every payload (recursively) against 22 known prompt injection patterns and Unicode homoglyph obfuscation. Detected payloads are quarantined — never chained, never persisted.
- **Audit chain:** Each validated decision produces an `AuditEntry` with:
  - `input_hash`: SHA256 of the original payload (exact reproducibility)
  - `entry_hash`: SHA256 of all entry fields canonically serialized
  - `previous_hash`: hash of the preceding chain entry (tamper detection)
  - `signature`: HMAC-SHA256 signed by governance's secret key
- **ATLAS mapping:** AML0043 (Prompt Injection) — detection and quarantine

### 3.4 Orchestrator
- **Purpose:** Entry point, HITL controller, real-time dashboard bridge
- **Fan-out:** Every injected transaction is simultaneously pushed to governance stream, detection agent stream, and compliance agent stream
- **HITL queue:** In-memory state machine with three states — PENDING, APPROVED/REJECTED, SUSPENDED. Operator can resolve any decision via REST API.
- **Explainability:** Generates plain-English explanation cards per HITL decision using transaction fields, AML regulation references, and risk-level-appropriate recommended actions
- **ATLAS tracker:** Maintains live counts per MITRE ATLAS technique, updated from the decisions stream

### 3.5 Operator Dashboard
- **Live feed:** WebSocket connection to orchestrator, auto-reconnects, displays all agent events color-coded by type
- **HITL queue:** Polls `/hitl/pending` every 3 seconds, shows explainability cards with regulation citations and recommended actions
- **ATLAS panel:** Polls `/atlas/threats` every 5 seconds, shows technique status (MONITORING/ACTIVE/BLOCKED) with pulsing indicators
- **Audit log:** Displays signed chain entries with entry hash, previous hash, and HMAC signature visible
- **Network graph:** Canvas force-directed graph of account→country transaction flows, red edges for high-risk transactions
- **Red Team button:** Triggers a live prompt injection demo — crafted payload enters the pipeline, governance quarantines it, ATLAS panel updates, screen flashes red

---

## 4. Security Architecture

### 4.1 Zero Trust Enforcement

Zero trust is enforced at every inter-component boundary:

| Boundary | Mechanism |
|---|---|
| Simulator → Orchestrator | HTTPS REST (local: HTTP) |
| Orchestrator → Redis Streams | JWT HS256 signed message payload |
| Agent → Redis Streams | JWT HS256 signed via `BaseAgent.publish()` |
| Governance ← Redis Streams | JWT verified before any processing |
| Governance → PostgreSQL | asyncpg authenticated connection |
| Governance → Decisions Stream | Signed AuditEntry serialized to JSON |
| Dashboard → Orchestrator | WebSocket + REST (JWT-protected in prod) |

No component trusts another implicitly. Every message on the bus carries a short-lived (30s TTL) JWT signed by the sender's secret. Governance verifies each one before chaining.

### 4.2 Signed & Chained Audit Log

Each `AuditEntry` is constructed as follows:

```
content = canonical_json({
    id, sequence, timestamp, agent_id, agent_version,
    correlation_id, decision_type, input_hash,
    decision, rationale, previous_hash
})

entry_hash = SHA256(content)
signature  = HMAC-SHA256(entry_hash, governance_secret)
```

Tampering with any field changes `entry_hash`, breaking the chain at that point. Forging a valid `signature` requires the governance secret. Every decision is reproducible from its `input_hash` and the exact agent version recorded in `agent_version`.

### 4.3 Prompt Injection Guardrails

The injection guard (`services/governance/injection_guard.py`) runs before any chaining:

1. **Pattern matching:** 22 known injection strings scanned across all string values recursively in the payload
2. **Unicode homoglyph detection:** Non-Latin characters beyond U+024F flagged (Cyrillic, Greek, Arabic mixed into Latin text)
3. **Quarantine on detection:** Payload is never persisted. A `PROMPT_INJECTION_DETECTED` alert is published to the decisions stream (visible on dashboard) and forwarded to Wazuh at severity level 15 (CRITICAL).

### 4.4 Human-in-the-Loop (HITL)

The HITL queue intercepts any decision where:
- Detection Agent: `risk_score ≥ 0.7` (CRITICAL tier)
- Compliance Agent: `sanctions_hit = true` OR `pep_hit = true`

The operator sees:
- Risk level badge (CRITICAL/HIGH/MEDIUM/LOW)
- Plain-English reasons with regulation citations (AML 6th, DORA, MiFID II)
- Specific recommended action ("Immediately freeze account and escalate to Compliance Officer")
- Raw decision payload for reference

The operator can **Approve**, **Reject**, or **Suspend** any decision. Suspended decisions freeze in-place for further investigation. The resolution is broadcast to all connected dashboard clients in real time.

---

## 5. MITRE ATLAS Threat Model

### 5.1 Applicable Techniques

| Technique | Name | Attack Scenario | Control |
|---|---|---|---|
| **AML0043** | Prompt Injection | Adversary injects malicious instructions into transaction payload fields (e.g., `note`, `description`) to manipulate agent decisions | Injection guard with 22-pattern + homoglyph detection; quarantine before chaining; ATLAS tracker |
| **AML0054** | LLM Jailbreak / Auth Bypass | Adversary attempts to submit messages without valid JWT, or with expired/tampered tokens, to bypass governance validation | JWT HS256 verification on every message; `AuthError` → quarantine; ATLAS AML0054 counter |
| **AML0015** | Evade ML Model | Adversary crafts transactions that individually score below thresholds but collectively represent fraud patterns | HITL for CRITICAL decisions; signed chain makes every decision auditable; velocity checks in detection agent |
| **AML0002** | Backdoor ML Model | Adversary attempts to inject persistent malicious behavior via model inputs | SHA256-chained audit log with `input_hash` — every decision is reproducible from its exact input; agent version recorded |

### 5.2 Threat Mitigations Mapped to Code

```
AML0043 Prompt Injection
  └─ Detection:    services/governance/injection_guard.py:detect_injection()
  └─ Response:     governance/main.py:process_message() → return without chaining
  └─ Alerting:     Wazuh level-15 + DECISIONS_STREAM broadcast
  └─ Tracking:     orchestrator/atlas.py → AML0043.blocked += 1
  └─ Demo:         POST /redteam/inject → live quarantine visible on dashboard

AML0054 Auth Bypass
  └─ Detection:    services/orchestrator/auth.py:verify_message() → AuthError
  └─ Response:     governance/main.py → log warning, send AGENT_ERROR to Wazuh, return
  └─ Tracking:     orchestrator/atlas.py → AML0054.attempts += 1

AML0015 Evade ML Model
  └─ Detection:    detection_agent/agent.py:requires_hitl() → score ≥ 0.7
  └─ Response:     HITL queue → human operator decides before execution
  └─ Tracking:     orchestrator/atlas.py → AML0015 monitoring

AML0002 Backdoor ML Model
  └─ Detection:    governance/chain.py:verify_entry() → ChainVerificationError
  └─ Evidence:     audit_chain.input_hash + audit_chain.agent_version per entry
  └─ Audit:        Every decision reproducible from input_hash + agent_version
```

### 5.3 Residual Risks

| Risk | Likelihood | Mitigation Path |
|---|---|---|
| Novel injection patterns not in the 22-pattern list | Medium | Extend `INJECTION_PATTERNS` list; add semantic similarity check |
| Governance secret compromise | Low | Rotate secret; all signatures invalidated; new chain begins |
| Redis Streams message interception | Low | TLS on Redis in production (`rediss://`); current: trusted network |
| Agent collusion (both agents compromised) | Very Low | Governance validates independently; human always has final authority |

---

## 6. Technical Choices

| Choice | Rationale |
|---|---|
| **Redis Streams** | Ordered, consumer-group-aware message bus. Built-in message acknowledgement prevents data loss. Each agent is an independent consumer group — agents can be scaled horizontally without code changes. |
| **HS256 JWT (python-jose)** | Lightweight, stateless inter-service authentication. Short TTL (30s) limits replay window. Per-service secrets mean a compromised agent cannot forge governance messages. |
| **SHA256 + HMAC chain (stdlib only)** | No external dependency for the most security-critical component. Canonical JSON serialization (sort_keys=True) ensures deterministic hashing regardless of field insertion order. |
| **FastAPI + asyncio** | Native async throughout — WebSocket broadcast, Redis Streams reads, and PostgreSQL queries all run concurrently without blocking. |
| **asyncpg** | Fastest PostgreSQL driver for Python. Direct binary protocol — no ORM overhead for the audit chain inserts which happen on every transaction. |
| **Pydantic v2** | Schema validation at every boundary. Shared `events.py` schema between Python services and TypeScript dashboard. Breaking changes fail fast at startup. |
| **React + Canvas (no graph lib)** | The force-directed network graph is implemented directly on HTML Canvas to avoid adding a heavy D3 or Cytoscape dependency. Custom Fruchterman-Reingold spring simulation in ~80 lines. |
| **Wazuh (open-source SIEM)** | Free, Docker-native, widely used in banking contexts. Custom rule definitions (`custom-rules.xml`) map MAS event types to Wazuh severity levels. |

---

## 7. Regulatory Compliance Mapping

| Requirement | Implementation |
|---|---|
| **DORA** — ICT incident reporting | Every agent error and HITL trigger is logged to the signed audit chain with exact timestamp and agent version |
| **AML 6th Directive** — Suspicious Activity Reporting | Compliance agent detects structuring, high-risk sector, and sanctions patterns; HITL queue surfaces SAR obligations in plain English |
| **GDPR** — Data minimization | Transaction payloads stored as JSON in audit chain; no customer PII beyond account ID |
| **EU AI Act** — High-risk AI system transparency | Every decision includes `rationale` (human-readable), `input_hash` (exact reproducibility), `agent_version` (model accountability) |
| **MiFID II** — Suitability assessment | Merchant category checks in compliance agent flag gambling/crypto for enhanced due diligence |
| **Basel IV** — Operational risk | DORA resilience via consumer-group Redis Streams (no single point of failure between agents) |

---

## 8. Deployment

```bash
# Prerequisites: Docker Desktop running

cp .env.example .env
# Edit GOVERNANCE_SECRET, ORCHESTRATOR_SECRET to strong 32+ char secrets

docker compose up --build -d

# Start transaction simulator
pip install httpx
python3 simulator/simulate.py

# Dashboard: http://localhost:3000
# API:       http://localhost:8000
```

**Services:**

| Service | Port | Role |
|---|---|---|
| Orchestrator | 8000 | Entry point, REST API, WebSocket |
| Dashboard | 3000 | Operator console (nginx) |
| Redis | 6379 | Message bus |
| PostgreSQL | 5432 | Audit chain storage |
| Detection Agent | — | Background worker |
| Compliance Agent | — | Background worker |
| Governance | — | Background worker |
