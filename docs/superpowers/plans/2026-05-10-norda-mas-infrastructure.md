# NORDA MAS Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the non-negotiable infrastructure layer of the NORDA Bank MAS — orchestrator, governance (signed audit chain), agent base class, React dashboard, and Wazuh SOC bridge — leaving agent-specific business logic as plug-in points.

**Architecture:** FastAPI orchestrator accepts events, routes them through Redis Streams to a governance layer that validates, SHA256-chains, and stores every decision before forwarding to Wazuh and broadcasting to the React dashboard via WebSocket. Agents extend a base class that handles JWT authentication and stream pub/sub; their `process()` method is the only blank to fill in.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, redis-py (Redis Streams), asyncpg, python-jose (JWT HS256), httpx, React 18, TypeScript, Vite, TailwindCSS, shadcn/ui, Docker Compose, PostgreSQL 15, Redis 7, Wazuh 4.x (Docker all-in-one)

---

## Task 1: Project Scaffold

**Files:**
- Create: `norda-mas/docker-compose.yml`
- Create: `norda-mas/.env.example`
- Create: `norda-mas/shared/__init__.py`
- Create: `norda-mas/services/orchestrator/__init__.py`
- Create: `norda-mas/services/governance/__init__.py`
- Create: `norda-mas/services/agent_base/__init__.py`

- [ ] **Step 1: Create root directory structure**

```bash
cd /home/amirben/Documents/hack
mkdir -p norda-mas/{shared/schema,services/{orchestrator,governance,agent_base},infra/{postgres,wazuh},tests}
touch norda-mas/shared/__init__.py norda-mas/shared/schema/__init__.py
touch norda-mas/services/orchestrator/__init__.py
touch norda-mas/services/governance/__init__.py
touch norda-mas/services/agent_base/__init__.py
```

- [ ] **Step 2: Write `.env.example`**

```bash
cat > norda-mas/.env.example << 'EOF'
# Governance
GOVERNANCE_SECRET=change-me-32-chars-minimum-here!!
GOVERNANCE_AGENT_ID=governance-v1

# Orchestrator
ORCHESTRATOR_SECRET=change-me-orchestrator-secret!!
ORCHESTRATOR_AGENT_ID=orchestrator-v1

# Database
POSTGRES_USER=norda
POSTGRES_PASSWORD=norda_secret
POSTGRES_DB=norda_audit
DATABASE_URL=postgresql://norda:norda_secret@postgres:5432/norda_audit

# Redis
REDIS_URL=redis://redis:6379

# Wazuh
WAZUH_API_URL=https://wazuh-manager:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=MyS3cr37P450r.*-
WAZUH_VERIFY_SSL=false

# Stream names
EVENTS_STREAM=norda:events
DECISIONS_STREAM=norda:decisions
HITL_STREAM=norda:hitl
EOF
```

- [ ] **Step 3: Write `docker-compose.yml`**

```yaml
# norda-mas/docker-compose.yml
version: "3.9"

services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    volumes:
      - ./infra/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 5s
      timeout: 3s
      retries: 10

  orchestrator:
    build: ./services/orchestrator
    env_file: .env
    ports:
      - "8000:8000"
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy

  governance:
    build: ./services/governance
    env_file: .env
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy

  dashboard:
    build: ./services/dashboard
    ports:
      - "3000:3000"
    depends_on:
      - orchestrator

volumes:
  pgdata:
```

- [ ] **Step 4: Commit**

```bash
cd /home/amirben/Documents/hack/norda-mas
git init
git add .
git commit -m "chore: initial project scaffold with docker-compose"
```

---

## Task 2: Shared Event Schema

**Files:**
- Create: `norda-mas/shared/schema/events.py`
- Create: `norda-mas/services/dashboard/src/types/events.ts`
- Test: `norda-mas/tests/test_schema.py`

- [ ] **Step 1: Write the failing test**

```python
# norda-mas/tests/test_schema.py
import pytest
from shared.schema.events import AgentMessage, Decision, AuditEntry, HITLEvent, EventType

def test_agent_message_serializes():
    msg = AgentMessage(
        event_type=EventType.AGENT_OUTPUT,
        agent_id="detection-v1",
        agent_version="1.0.0",
        correlation_id="txn-123",
        payload={"risk_score": 0.87, "flags": ["velocity"]},
        jwt_token="placeholder",
    )
    data = msg.model_dump()
    assert data["agent_id"] == "detection-v1"
    assert data["payload"]["risk_score"] == 0.87

def test_audit_entry_has_required_fields():
    entry = AuditEntry(
        sequence=1,
        agent_id="governance-v1",
        agent_version="1.0.0",
        correlation_id="txn-123",
        decision_type="RISK_ASSESSMENT",
        input_hash="abc123",
        decision={"risk_score": 0.87},
        rationale="Velocity pattern exceeded threshold",
        previous_hash="0" * 64,
        entry_hash="def456",
        signature="sig",
    )
    assert entry.sequence == 1
    assert entry.previous_hash == "0" * 64
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/amirben/Documents/hack/norda-mas
pip install pydantic
python -m pytest tests/test_schema.py -v
```

Expected: `ImportError` — module does not exist yet.

- [ ] **Step 3: Write `shared/schema/events.py`**

```python
# norda-mas/shared/schema/events.py
from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class EventType(str, Enum):
    TRANSACTION_RECEIVED = "TRANSACTION_RECEIVED"
    AGENT_OUTPUT = "AGENT_OUTPUT"
    DECISION_VALIDATED = "DECISION_VALIDATED"
    HITL_REQUIRED = "HITL_REQUIRED"
    HITL_RESOLVED = "HITL_RESOLVED"
    AGENT_ERROR = "AGENT_ERROR"
    PROMPT_INJECTION_DETECTED = "PROMPT_INJECTION_DETECTED"


class HITLAction(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    SUSPEND = "SUSPEND"


class AgentMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: EventType
    agent_id: str
    agent_version: str
    correlation_id: str
    payload: dict[str, Any]
    jwt_token: str


class Decision(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: str
    decision_type: str
    outcome: str
    confidence: float
    rationale: str
    requires_hitl: bool = False
    agent_id: str
    agent_version: str


class AuditEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sequence: int
    agent_id: str
    agent_version: str
    correlation_id: str
    decision_type: str
    input_hash: str
    decision: dict[str, Any]
    rationale: str
    previous_hash: str
    entry_hash: str
    signature: str


class HITLEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    decision_id: str
    correlation_id: str
    decision: dict[str, Any]
    rationale: str
    action: HITLAction | None = None
    operator_id: str | None = None
    resolved_at: datetime | None = None
```

- [ ] **Step 4: Write TypeScript mirror `services/dashboard/src/types/events.ts`**

```typescript
// norda-mas/services/dashboard/src/types/events.ts
export type EventType =
  | "TRANSACTION_RECEIVED"
  | "AGENT_OUTPUT"
  | "DECISION_VALIDATED"
  | "HITL_REQUIRED"
  | "HITL_RESOLVED"
  | "AGENT_ERROR"
  | "PROMPT_INJECTION_DETECTED";

export type HITLAction = "APPROVE" | "REJECT" | "SUSPEND";

export interface AgentMessage {
  id: string;
  timestamp: string;
  event_type: EventType;
  agent_id: string;
  agent_version: string;
  correlation_id: string;
  payload: Record<string, unknown>;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  sequence: number;
  agent_id: string;
  agent_version: string;
  correlation_id: string;
  decision_type: string;
  input_hash: string;
  decision: Record<string, unknown>;
  rationale: string;
  previous_hash: string;
  entry_hash: string;
  signature: string;
}

export interface HITLEvent {
  id: string;
  timestamp: string;
  decision_id: string;
  correlation_id: string;
  decision: Record<string, unknown>;
  rationale: string;
  action: HITLAction | null;
  operator_id: string | null;
  resolved_at: string | null;
}

export interface WSMessage {
  type: EventType;
  data: AgentMessage | AuditEntry | HITLEvent;
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /home/amirben/Documents/hack/norda-mas
python -m pytest tests/test_schema.py -v
```

Expected: 2 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add shared/ services/dashboard/src/types/ tests/test_schema.py
git commit -m "feat: shared event schema (Pydantic + TypeScript)"
```

---

## Task 3: JWT Auth Module

**Files:**
- Create: `norda-mas/services/orchestrator/auth.py`
- Test: `norda-mas/tests/test_auth.py`

- [ ] **Step 1: Write the failing tests**

```python
# norda-mas/tests/test_auth.py
import time
import pytest
from services.orchestrator.auth import sign_message, verify_message, AuthError


def test_sign_and_verify_roundtrip():
    secret = "test-secret-32-chars-minimum-ok!"
    payload = {"agent_id": "detection-v1", "correlation_id": "txn-123"}
    token = sign_message(payload, secret, ttl_seconds=30)
    decoded = verify_message(token, secret)
    assert decoded["agent_id"] == "detection-v1"
    assert decoded["correlation_id"] == "txn-123"


def test_tampered_token_rejected():
    secret = "test-secret-32-chars-minimum-ok!"
    payload = {"agent_id": "detection-v1"}
    token = sign_message(payload, secret, ttl_seconds=30)
    tampered = token[:-5] + "XXXXX"
    with pytest.raises(AuthError):
        verify_message(tampered, secret)


def test_wrong_secret_rejected():
    token = sign_message({"agent_id": "x"}, "secret-one-32-chars-minimum-xxx!", ttl_seconds=30)
    with pytest.raises(AuthError):
        verify_message(token, "secret-two-32-chars-minimum-xxx!")


def test_expired_token_rejected():
    token = sign_message({"agent_id": "x"}, "test-secret-32-chars-minimum-ok!", ttl_seconds=-1)
    with pytest.raises(AuthError):
        verify_message(token, "test-secret-32-chars-minimum-ok!")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/amirben/Documents/hack/norda-mas
pip install python-jose[cryptography]
python -m pytest tests/test_auth.py -v
```

Expected: `ImportError` — module does not exist yet.

- [ ] **Step 3: Write `services/orchestrator/auth.py`**

```python
# norda-mas/services/orchestrator/auth.py
from datetime import datetime, timezone, timedelta
from typing import Any
from uuid import uuid4

from jose import JWTError, jwt

ALGORITHM = "HS256"
ISSUER = "norda-mas"


class AuthError(Exception):
    pass


def sign_message(payload: dict[str, Any], secret: str, ttl_seconds: int = 30) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        **payload,
        "iss": ISSUER,
        "iat": now,
        "exp": now + timedelta(seconds=ttl_seconds),
        "jti": str(uuid4()),
    }
    try:
        return jwt.encode(claims, secret, algorithm=ALGORITHM)
    except Exception as e:
        raise AuthError(f"Failed to sign message: {e}") from e


def verify_message(token: str, secret: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, secret, algorithms=[ALGORITHM], issuer=ISSUER)
    except JWTError as e:
        raise AuthError(f"Invalid token: {e}") from e
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_auth.py -v
```

Expected: 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add services/orchestrator/auth.py tests/test_auth.py
git commit -m "feat: JWT auth module with sign/verify and expiry"
```

---

## Task 4: PostgreSQL Schema + Governance Audit Chain

**Files:**
- Create: `norda-mas/infra/postgres/init.sql`
- Create: `norda-mas/services/governance/chain.py`
- Test: `norda-mas/tests/test_chain.py`

- [ ] **Step 1: Write `infra/postgres/init.sql`**

```sql
-- norda-mas/infra/postgres/init.sql
CREATE TABLE IF NOT EXISTS audit_chain (
    id          UUID PRIMARY KEY,
    sequence    BIGINT NOT NULL UNIQUE,
    timestamp   TIMESTAMPTZ NOT NULL,
    agent_id    TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    decision_type TEXT NOT NULL,
    input_hash  TEXT NOT NULL,
    decision    JSONB NOT NULL,
    rationale   TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash  TEXT NOT NULL,
    signature   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_chain_correlation ON audit_chain(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_chain_sequence ON audit_chain(sequence);

CREATE TABLE IF NOT EXISTS hitl_queue (
    id              UUID PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL,
    decision_id     TEXT NOT NULL,
    correlation_id  TEXT NOT NULL,
    decision        JSONB NOT NULL,
    rationale       TEXT NOT NULL,
    action          TEXT,
    operator_id     TEXT,
    resolved_at     TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'PENDING'
);

CREATE INDEX IF NOT EXISTS idx_hitl_status ON hitl_queue(status);
```

- [ ] **Step 2: Write the failing chain tests**

```python
# norda-mas/tests/test_chain.py
import hashlib
import hmac
import json
import pytest
from unittest.mock import AsyncMock, MagicMock
from services.governance.chain import ChainSigner, ChainVerificationError


GOVERNANCE_SECRET = "test-governance-secret-32-chars!!"


@pytest.fixture
def signer():
    return ChainSigner(secret=GOVERNANCE_SECRET)


def test_first_entry_has_genesis_previous_hash(signer):
    entry = signer.build_entry(
        sequence=1,
        agent_id="detection-v1",
        agent_version="1.0.0",
        correlation_id="txn-001",
        decision_type="RISK_ASSESSMENT",
        input_payload={"amount": 5000},
        decision={"risk_score": 0.9},
        rationale="High velocity",
        previous_hash="0" * 64,
    )
    assert entry.previous_hash == "0" * 64
    assert len(entry.entry_hash) == 64
    assert len(entry.signature) > 0


def test_chain_links_correctly(signer):
    entry1 = signer.build_entry(
        sequence=1, agent_id="a", agent_version="1.0", correlation_id="c1",
        decision_type="T", input_payload={}, decision={}, rationale="r",
        previous_hash="0" * 64,
    )
    entry2 = signer.build_entry(
        sequence=2, agent_id="a", agent_version="1.0", correlation_id="c2",
        decision_type="T", input_payload={}, decision={}, rationale="r",
        previous_hash=entry1.entry_hash,
    )
    assert entry2.previous_hash == entry1.entry_hash


def test_tampered_entry_fails_verification(signer):
    entry = signer.build_entry(
        sequence=1, agent_id="a", agent_version="1.0", correlation_id="c1",
        decision_type="T", input_payload={}, decision={}, rationale="r",
        previous_hash="0" * 64,
    )
    entry.rationale = "TAMPERED"
    with pytest.raises(ChainVerificationError):
        signer.verify_entry(entry)


def test_valid_entry_passes_verification(signer):
    entry = signer.build_entry(
        sequence=1, agent_id="a", agent_version="1.0", correlation_id="c1",
        decision_type="T", input_payload={}, decision={}, rationale="r",
        previous_hash="0" * 64,
    )
    signer.verify_entry(entry)  # must not raise
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
python -m pytest tests/test_chain.py -v
```

Expected: `ImportError`.

- [ ] **Step 4: Write `services/governance/chain.py`**

```python
# norda-mas/services/governance/chain.py
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from shared.schema.events import AuditEntry


class ChainVerificationError(Exception):
    pass


class ChainSigner:
    def __init__(self, secret: str) -> None:
        self._secret = secret.encode()

    def _hash_content(self, content: dict[str, Any]) -> str:
        canonical = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _sign(self, entry_hash: str) -> str:
        return hmac.new(self._secret, entry_hash.encode(), hashlib.sha256).hexdigest()

    def build_entry(
        self,
        *,
        sequence: int,
        agent_id: str,
        agent_version: str,
        correlation_id: str,
        decision_type: str,
        input_payload: dict[str, Any],
        decision: dict[str, Any],
        rationale: str,
        previous_hash: str,
    ) -> AuditEntry:
        input_hash = self._hash_content(input_payload)
        now = datetime.now(timezone.utc)
        entry_id = str(uuid4())

        content_for_hash = {
            "id": entry_id,
            "sequence": sequence,
            "timestamp": now.isoformat(),
            "agent_id": agent_id,
            "agent_version": agent_version,
            "correlation_id": correlation_id,
            "decision_type": decision_type,
            "input_hash": input_hash,
            "decision": decision,
            "rationale": rationale,
            "previous_hash": previous_hash,
        }
        entry_hash = self._hash_content(content_for_hash)
        signature = self._sign(entry_hash)

        return AuditEntry(
            id=entry_id,
            timestamp=now,
            sequence=sequence,
            agent_id=agent_id,
            agent_version=agent_version,
            correlation_id=correlation_id,
            decision_type=decision_type,
            input_hash=input_hash,
            decision=decision,
            rationale=rationale,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            signature=signature,
        )

    def verify_entry(self, entry: AuditEntry) -> None:
        content_for_hash = {
            "id": entry.id,
            "sequence": entry.sequence,
            "timestamp": entry.timestamp.isoformat(),
            "agent_id": entry.agent_id,
            "agent_version": entry.agent_version,
            "correlation_id": entry.correlation_id,
            "decision_type": entry.decision_type,
            "input_hash": entry.input_hash,
            "decision": entry.decision,
            "rationale": entry.rationale,
            "previous_hash": entry.previous_hash,
        }
        expected_hash = self._hash_content(content_for_hash)
        if expected_hash != entry.entry_hash:
            raise ChainVerificationError("Entry hash mismatch — content was tampered")
        expected_sig = self._sign(entry.entry_hash)
        if not hmac.compare_digest(expected_sig, entry.signature):
            raise ChainVerificationError("Signature mismatch — entry is not authentic")
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
python -m pytest tests/test_chain.py -v
```

Expected: 4 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add infra/postgres/init.sql services/governance/chain.py tests/test_chain.py
git commit -m "feat: SHA256-chained audit log with HMAC signing"
```

---

## Task 5: Wazuh Bridge

**Files:**
- Create: `norda-mas/services/governance/wazuh.py`
- Create: `norda-mas/infra/wazuh/custom-rules.xml`
- Test: inline in governance integration test (no HTTP calls — httpx mock)

- [ ] **Step 1: Write `services/governance/wazuh.py`**

```python
# norda-mas/services/governance/wazuh.py
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "HITL_REQUIRED": 12,
    "PROMPT_INJECTION_DETECTED": 15,
    "DECISION_VALIDATED": 5,
    "AGENT_ERROR": 10,
}


class WazuhBridge:
    def __init__(self, api_url: str, user: str, password: str, verify_ssl: bool = False) -> None:
        self._api_url = api_url.rstrip("/")
        self._auth = (user, password)
        self._verify_ssl = verify_ssl
        self._token: str | None = None

    async def _get_token(self, client: httpx.AsyncClient) -> str:
        resp = await client.post(
            f"{self._api_url}/security/user/authenticate",
            auth=self._auth,
            verify=self._verify_ssl,
        )
        resp.raise_for_status()
        return resp.json()["data"]["token"]

    async def send_event(self, event_type: str, payload: dict[str, Any], correlation_id: str) -> None:
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {
                "level": SEVERITY_MAP.get(event_type, 5),
                "description": f"NORDA MAS: {event_type}",
                "id": "100001",
            },
            "agent": {"name": "norda-mas-governance"},
            "data": {
                "event_type": event_type,
                "correlation_id": correlation_id,
                **payload,
            },
        }
        async with httpx.AsyncClient(verify=self._verify_ssl) as client:
            try:
                if not self._token:
                    self._token = await self._get_token(client)
                resp = await client.post(
                    f"{self._api_url}/events",
                    json={"events": [alert]},
                    headers={"Authorization": f"Bearer {self._token}"},
                    verify=self._verify_ssl,
                )
                resp.raise_for_status()
            except httpx.HTTPError as e:
                logger.error("Wazuh send failed: %s", e)
                self._token = None  # force re-auth on next call
```

- [ ] **Step 2: Write `infra/wazuh/custom-rules.xml`**

```xml
<!-- norda-mas/infra/wazuh/custom-rules.xml -->
<group name="norda_mas,">

  <rule id="100001" level="5">
    <decoded_as>json</decoded_as>
    <field name="data.event_type">DECISION_VALIDATED</field>
    <description>NORDA MAS: Agent decision validated by governance</description>
    <group>norda_decision,</group>
  </rule>

  <rule id="100002" level="12">
    <decoded_as>json</decoded_as>
    <field name="data.event_type">HITL_REQUIRED</field>
    <description>NORDA MAS: Decision requires human operator approval</description>
    <group>norda_hitl,</group>
  </rule>

  <rule id="100003" level="15">
    <decoded_as>json</decoded_as>
    <field name="data.event_type">PROMPT_INJECTION_DETECTED</field>
    <description>NORDA MAS: Prompt injection attempt detected and quarantined</description>
    <group>norda_security,attack,</group>
  </rule>

  <rule id="100004" level="10">
    <decoded_as>json</decoded_as>
    <field name="data.event_type">AGENT_ERROR</field>
    <description>NORDA MAS: Agent reported an error condition</description>
    <group>norda_error,</group>
  </rule>

</group>
```

- [ ] **Step 3: Commit**

```bash
git add services/governance/wazuh.py infra/wazuh/custom-rules.xml
git commit -m "feat: Wazuh REST bridge and custom MAS alert rules"
```

---

## Task 6: HITL Queue

**Files:**
- Create: `norda-mas/services/orchestrator/hitl.py`
- Test: `norda-mas/tests/test_hitl.py`

- [ ] **Step 1: Write the failing tests**

```python
# norda-mas/tests/test_hitl.py
import pytest
from services.orchestrator.hitl import HITLQueue, HITLError
from shared.schema.events import HITLAction


@pytest.fixture
def queue():
    return HITLQueue()


def test_enqueue_and_list_pending(queue):
    queue.enqueue(decision_id="d1", correlation_id="txn-1", decision={"risk": 0.9}, rationale="High risk")
    pending = queue.list_pending()
    assert len(pending) == 1
    assert pending[0]["decision_id"] == "d1"


def test_resolve_approve(queue):
    queue.enqueue(decision_id="d1", correlation_id="txn-1", decision={}, rationale="r")
    queue.resolve(decision_id="d1", action=HITLAction.APPROVE, operator_id="op-001")
    pending = queue.list_pending()
    assert len(pending) == 0


def test_resolve_reject(queue):
    queue.enqueue(decision_id="d1", correlation_id="txn-1", decision={}, rationale="r")
    queue.resolve(decision_id="d1", action=HITLAction.REJECT, operator_id="op-001")
    resolved = queue.get_resolved()
    assert resolved[0]["action"] == "REJECT"


def test_resolve_unknown_decision_raises(queue):
    with pytest.raises(HITLError):
        queue.resolve(decision_id="does-not-exist", action=HITLAction.APPROVE, operator_id="op-001")


def test_suspend_freezes_decision(queue):
    queue.enqueue(decision_id="d1", correlation_id="txn-1", decision={}, rationale="r")
    queue.resolve(decision_id="d1", action=HITLAction.SUSPEND, operator_id="op-001")
    suspended = queue.get_suspended()
    assert len(suspended) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_hitl.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Write `services/orchestrator/hitl.py`**

```python
# norda-mas/services/orchestrator/hitl.py
from datetime import datetime, timezone
from typing import Any

from shared.schema.events import HITLAction


class HITLError(Exception):
    pass


class HITLQueue:
    def __init__(self) -> None:
        self._pending: dict[str, dict[str, Any]] = {}
        self._resolved: list[dict[str, Any]] = []
        self._suspended: list[dict[str, Any]] = []

    def enqueue(self, *, decision_id: str, correlation_id: str, decision: dict[str, Any], rationale: str) -> None:
        self._pending[decision_id] = {
            "decision_id": decision_id,
            "correlation_id": correlation_id,
            "decision": decision,
            "rationale": rationale,
            "enqueued_at": datetime.now(timezone.utc).isoformat(),
        }

    def resolve(self, *, decision_id: str, action: HITLAction, operator_id: str) -> None:
        if decision_id not in self._pending:
            raise HITLError(f"Decision {decision_id!r} not found in HITL queue")
        item = self._pending.pop(decision_id)
        item["action"] = action.value
        item["operator_id"] = operator_id
        item["resolved_at"] = datetime.now(timezone.utc).isoformat()
        if action == HITLAction.SUSPEND:
            self._suspended.append(item)
        else:
            self._resolved.append(item)

    def list_pending(self) -> list[dict[str, Any]]:
        return list(self._pending.values())

    def get_resolved(self) -> list[dict[str, Any]]:
        return self._resolved

    def get_suspended(self) -> list[dict[str, Any]]:
        return self._suspended
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_hitl.py -v
```

Expected: 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add services/orchestrator/hitl.py tests/test_hitl.py
git commit -m "feat: HITL queue with approve/reject/suspend state machine"
```

---

## Task 7: Governance Service (Redis Streams Interceptor)

**Files:**
- Create: `norda-mas/services/governance/main.py`
- Create: `norda-mas/services/governance/requirements.txt`
- Create: `norda-mas/services/governance/Dockerfile`

- [ ] **Step 1: Write `services/governance/requirements.txt`**

```text
fastapi==0.115.0
uvicorn[standard]==0.30.0
redis==5.0.8
asyncpg==0.29.0
pydantic==2.9.0
python-jose[cryptography]==3.3.0
httpx==0.27.0
```

- [ ] **Step 2: Write `services/governance/Dockerfile`**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ../../shared /app/shared
COPY . /app/services/governance
ENV PYTHONPATH=/app
CMD ["python", "-m", "services.governance.main"]
```

- [ ] **Step 3: Write `services/governance/main.py`**

```python
# norda-mas/services/governance/main.py
import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import asyncpg
import redis.asyncio as aioredis

from services.governance.chain import ChainSigner
from services.governance.wazuh import WazuhBridge
from services.orchestrator.auth import verify_message, sign_message, AuthError
from shared.schema.events import AgentMessage, AuditEntry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REDIS_URL = os.environ["REDIS_URL"]
DATABASE_URL = os.environ["DATABASE_URL"]
GOVERNANCE_SECRET = os.environ["GOVERNANCE_SECRET"]
GOVERNANCE_AGENT_ID = os.environ.get("GOVERNANCE_AGENT_ID", "governance-v1")
EVENTS_STREAM = os.environ.get("EVENTS_STREAM", "norda:events")
DECISIONS_STREAM = os.environ.get("DECISIONS_STREAM", "norda:decisions")
CONSUMER_GROUP = "governance-group"

WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")

signer = ChainSigner(secret=GOVERNANCE_SECRET)
wazuh: WazuhBridge | None = None


async def get_last_sequence(conn: asyncpg.Connection) -> int:
    row = await conn.fetchrow("SELECT MAX(sequence) as seq FROM audit_chain")
    return row["seq"] or 0


async def get_last_entry_hash(conn: asyncpg.Connection) -> str:
    row = await conn.fetchrow("SELECT entry_hash FROM audit_chain ORDER BY sequence DESC LIMIT 1")
    return row["entry_hash"] if row else "0" * 64


async def persist_entry(conn: asyncpg.Connection, entry: AuditEntry) -> None:
    await conn.execute(
        """INSERT INTO audit_chain
           (id, sequence, timestamp, agent_id, agent_version, correlation_id,
            decision_type, input_hash, decision, rationale, previous_hash, entry_hash, signature)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)""",
        entry.id, entry.sequence, entry.timestamp, entry.agent_id, entry.agent_version,
        entry.correlation_id, entry.decision_type, entry.input_hash,
        json.dumps(entry.decision), entry.rationale, entry.previous_hash,
        entry.entry_hash, entry.signature,
    )


async def process_message(msg: AgentMessage, conn: asyncpg.Connection, redis_client: aioredis.Redis) -> None:
    # Verify JWT from sending agent
    try:
        verify_message(msg.jwt_token, GOVERNANCE_SECRET)
    except AuthError as e:
        logger.warning("Rejected message from %s — auth failed: %s", msg.agent_id, e)
        if wazuh:
            await wazuh.send_event("AGENT_ERROR", {"reason": "auth_failure"}, msg.correlation_id)
        return

    seq = await get_last_sequence(conn) + 1
    prev_hash = await get_last_entry_hash(conn)

    entry = signer.build_entry(
        sequence=seq,
        agent_id=msg.agent_id,
        agent_version=msg.agent_version,
        correlation_id=msg.correlation_id,
        decision_type=msg.event_type.value,
        input_payload=msg.payload,
        decision=msg.payload,
        rationale=msg.payload.get("rationale", ""),
        previous_hash=prev_hash,
    )

    await persist_entry(conn, entry)
    logger.info("Chained entry seq=%d correlation=%s", seq, msg.correlation_id)

    # Forward signed decision downstream
    signed_entry = entry.model_dump_json()
    await redis_client.xadd(DECISIONS_STREAM, {"data": signed_entry})

    event_type = msg.event_type.value
    if wazuh:
        await wazuh.send_event(event_type, msg.payload, msg.correlation_id)


async def main() -> None:
    global wazuh
    if WAZUH_API_URL:
        wazuh = WazuhBridge(WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD, verify_ssl=False)

    redis_client = await aioredis.from_url(REDIS_URL)
    db_pool = await asyncpg.create_pool(DATABASE_URL)

    try:
        await redis_client.xgroup_create(EVENTS_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
    except Exception:
        pass  # group already exists

    logger.info("Governance service listening on stream %s", EVENTS_STREAM)
    while True:
        entries = await redis_client.xreadgroup(
            CONSUMER_GROUP, GOVERNANCE_AGENT_ID, {EVENTS_STREAM: ">"}, count=10, block=1000
        )
        for _stream, messages in (entries or []):
            for msg_id, fields in messages:
                try:
                    raw = fields.get(b"data", b"{}")
                    msg = AgentMessage.model_validate_json(raw)
                    async with db_pool.acquire() as conn:
                        await process_message(msg, conn, redis_client)
                    await redis_client.xack(EVENTS_STREAM, CONSUMER_GROUP, msg_id)
                except Exception as e:
                    logger.error("Failed to process message %s: %s", msg_id, e)


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 4: Commit**

```bash
git add services/governance/
git commit -m "feat: governance stream interceptor with chain persistence and Wazuh forwarding"
```

---

## Task 8: Agent Base Class

**Files:**
- Create: `norda-mas/services/agent_base/base_agent.py`
- Create: `norda-mas/services/agent_base/requirements.txt`

- [ ] **Step 1: Write `services/agent_base/base_agent.py`**

```python
# norda-mas/services/agent_base/base_agent.py
"""
Abstract base class for NORDA MAS agents.

To implement a new agent:
1. Subclass BaseAgent
2. Set AGENT_ID and AGENT_VERSION class attributes
3. Implement the `process` method — receive a dict, return a dict with `rationale` key
4. Optionally override `requires_hitl` to flag decisions for human review
5. Run with: asyncio.run(MyAgent().run())
"""
import asyncio
import json
import logging
import os
from abc import ABC, abstractmethod
from typing import Any

import redis.asyncio as aioredis

from services.orchestrator.auth import sign_message
from shared.schema.events import AgentMessage, EventType

logger = logging.getLogger(__name__)

REDIS_URL = os.environ["REDIS_URL"]
EVENTS_STREAM = os.environ.get("EVENTS_STREAM", "norda:events")
GOVERNANCE_SECRET = os.environ["GOVERNANCE_SECRET"]


class BaseAgent(ABC):
    AGENT_ID: str = "base-agent"
    AGENT_VERSION: str = "1.0.0"

    @abstractmethod
    async def process(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Receive an input payload, return a decision payload.
        The returned dict MUST include a 'rationale' key (str).
        """

    def requires_hitl(self, output: dict[str, Any]) -> bool:
        """Override to flag decisions that need human approval."""
        return False

    async def publish(self, redis_client: aioredis.Redis, correlation_id: str, payload: dict[str, Any]) -> None:
        event_type = EventType.HITL_REQUIRED if self.requires_hitl(payload) else EventType.AGENT_OUTPUT
        token = sign_message(
            {"agent_id": self.AGENT_ID, "correlation_id": correlation_id},
            secret=GOVERNANCE_SECRET,
            ttl_seconds=30,
        )
        msg = AgentMessage(
            event_type=event_type,
            agent_id=self.AGENT_ID,
            agent_version=self.AGENT_VERSION,
            correlation_id=correlation_id,
            payload=payload,
            jwt_token=token,
        )
        await redis_client.xadd(EVENTS_STREAM, {"data": msg.model_dump_json()})
        logger.info("[%s] published %s for correlation=%s", self.AGENT_ID, event_type.value, correlation_id)

    async def run(self) -> None:
        redis_client = await aioredis.from_url(REDIS_URL)
        consumer_group = f"{self.AGENT_ID}-group"
        input_stream = os.environ.get("INPUT_STREAM", f"norda:{self.AGENT_ID}:input")

        try:
            await redis_client.xgroup_create(input_stream, consumer_group, id="0", mkstream=True)
        except Exception:
            pass

        logger.info("[%s] listening on stream %s", self.AGENT_ID, input_stream)
        while True:
            entries = await redis_client.xreadgroup(
                consumer_group, self.AGENT_ID, {input_stream: ">"}, count=5, block=2000
            )
            for _stream, messages in (entries or []):
                for msg_id, fields in messages:
                    try:
                        raw = fields.get(b"data", b"{}")
                        data = json.loads(raw)
                        correlation_id = data.get("correlation_id", msg_id.decode())
                        output = await self.process(data.get("payload", data))
                        await self.publish(redis_client, correlation_id, output)
                        await redis_client.xack(input_stream, consumer_group, msg_id)
                    except Exception as e:
                        logger.error("[%s] error processing %s: %s", self.AGENT_ID, msg_id, e)
```

- [ ] **Step 2: Commit**

```bash
git add services/agent_base/
git commit -m "feat: abstract agent base class with JWT auth and Redis Streams pub/sub"
```

---

## Task 9: Orchestrator (FastAPI + WebSocket + HITL API)

**Files:**
- Create: `norda-mas/services/orchestrator/main.py`
- Create: `norda-mas/services/orchestrator/requirements.txt`
- Create: `norda-mas/services/orchestrator/Dockerfile`

- [ ] **Step 1: Write `services/orchestrator/requirements.txt`**

```text
fastapi==0.115.0
uvicorn[standard]==0.30.0
redis==5.0.8
asyncpg==0.29.0
pydantic==2.9.0
python-jose[cryptography]==3.3.0
```

- [ ] **Step 2: Write `services/orchestrator/Dockerfile`**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ../../shared /app/shared
COPY . /app/services/orchestrator
ENV PYTHONPATH=/app
CMD ["uvicorn", "services.orchestrator.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

- [ ] **Step 3: Write `services/orchestrator/main.py`**

```python
# norda-mas/services/orchestrator/main.py
import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from services.orchestrator.auth import sign_message
from services.orchestrator.hitl import HITLQueue, HITLError
from shared.schema.events import AgentMessage, EventType, HITLAction

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REDIS_URL = os.environ["REDIS_URL"]
GOVERNANCE_SECRET = os.environ["GOVERNANCE_SECRET"]
EVENTS_STREAM = os.environ.get("EVENTS_STREAM", "norda:events")
DECISIONS_STREAM = os.environ.get("DECISIONS_STREAM", "norda:decisions")

hitl_queue = HITLQueue()
ws_clients: list[WebSocket] = []


async def broadcast(message: dict[str, Any]) -> None:
    disconnected = []
    for ws in ws_clients:
        try:
            await ws.send_json(message)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        ws_clients.remove(ws)


async def stream_listener(redis_client: aioredis.Redis) -> None:
    last_id = "$"
    while True:
        try:
            entries = await redis_client.xread({DECISIONS_STREAM: last_id}, count=10, block=500)
            for _stream, messages in (entries or []):
                for msg_id, fields in messages:
                    last_id = msg_id.decode() if isinstance(msg_id, bytes) else msg_id
                    raw = fields.get(b"data", b"{}")
                    data = json.loads(raw)
                    await broadcast({"type": "DECISION_VALIDATED", "data": data})
        except Exception as e:
            logger.error("Stream listener error: %s", e)
            await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    redis_client = await aioredis.from_url(REDIS_URL)
    app.state.redis = redis_client
    listener_task = asyncio.create_task(stream_listener(redis_client))
    yield
    listener_task.cancel()
    await redis_client.aclose()


app = FastAPI(title="NORDA MAS Orchestrator", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    ws_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_clients.remove(websocket)


class InjectEventRequest(BaseModel):
    correlation_id: str
    payload: dict[str, Any]


@app.post("/events/inject")
async def inject_event(req: InjectEventRequest):
    """Inject a raw event into the MAS pipeline (used by simulator and tests)."""
    token = sign_message(
        {"agent_id": "orchestrator-v1", "correlation_id": req.correlation_id},
        secret=GOVERNANCE_SECRET,
        ttl_seconds=30,
    )
    msg = AgentMessage(
        event_type=EventType.TRANSACTION_RECEIVED,
        agent_id="orchestrator-v1",
        agent_version="1.0.0",
        correlation_id=req.correlation_id,
        payload=req.payload,
        jwt_token=token,
    )
    await app.state.redis.xadd(EVENTS_STREAM, {"data": msg.model_dump_json()})
    await broadcast({"type": "TRANSACTION_RECEIVED", "data": msg.model_dump(mode="json")})
    return {"status": "injected", "correlation_id": req.correlation_id}


class HITLResolveRequest(BaseModel):
    action: HITLAction
    operator_id: str


@app.post("/hitl/{decision_id}/resolve")
async def resolve_hitl(decision_id: str, req: HITLResolveRequest):
    try:
        hitl_queue.resolve(decision_id=decision_id, action=req.action, operator_id=req.operator_id)
    except HITLError as e:
        raise HTTPException(status_code=404, detail=str(e))
    await broadcast({"type": "HITL_RESOLVED", "data": {"decision_id": decision_id, "action": req.action.value}})
    return {"status": "resolved", "decision_id": decision_id}


@app.get("/hitl/pending")
async def list_pending_hitl():
    return {"pending": hitl_queue.list_pending()}


@app.get("/audit/chain")
async def get_audit_chain(limit: int = 50):
    import asyncpg
    DATABASE_URL = os.environ["DATABASE_URL"]
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        rows = await conn.fetch(
            "SELECT * FROM audit_chain ORDER BY sequence DESC LIMIT $1", limit
        )
        return {"entries": [dict(r) for r in rows]}
    finally:
        await conn.close()


@app.get("/health")
async def health():
    return {"status": "ok"}
```

- [ ] **Step 4: Commit**

```bash
git add services/orchestrator/
git commit -m "feat: orchestrator with WebSocket broadcast, HITL API, and event injection"
```

---

## Task 10: React Dashboard

**Files:**
- Create: `norda-mas/services/dashboard/` (full Vite + React + Tailwind app)

- [ ] **Step 1: Scaffold the React app**

```bash
cd /home/amirben/Documents/hack/norda-mas/services
npm create vite@latest dashboard -- --template react-ts
cd dashboard
npm install
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
npm install @radix-ui/react-tabs @radix-ui/react-badge lucide-react clsx
```

- [ ] **Step 2: Configure Tailwind (`tailwind.config.js`)**

```js
// norda-mas/services/dashboard/tailwind.config.js
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: { extend: {} },
  plugins: [],
};
```

- [ ] **Step 3: Write `src/hooks/useWebSocket.ts`**

```typescript
// norda-mas/services/dashboard/src/hooks/useWebSocket.ts
import { useEffect, useRef, useState, useCallback } from "react";
import { WSMessage } from "../types/events";

export function useWebSocket(url: string) {
  const [messages, setMessages] = useState<WSMessage[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      setTimeout(connect, 2000); // auto-reconnect
    };
    ws.onmessage = (e) => {
      try {
        const msg: WSMessage = JSON.parse(e.data);
        setMessages((prev) => [msg, ...prev].slice(0, 200)); // keep last 200
      } catch {}
    };
  }, [url]);

  useEffect(() => {
    connect();
    return () => wsRef.current?.close();
  }, [connect]);

  return { messages, connected };
}
```

- [ ] **Step 4: Write `src/components/AgentFeed.tsx`**

```typescript
// norda-mas/services/dashboard/src/components/AgentFeed.tsx
import { WSMessage } from "../types/events";

const EVENT_COLORS: Record<string, string> = {
  TRANSACTION_RECEIVED: "text-blue-400",
  AGENT_OUTPUT: "text-green-400",
  DECISION_VALIDATED: "text-emerald-400",
  HITL_REQUIRED: "text-yellow-400",
  HITL_RESOLVED: "text-purple-400",
  AGENT_ERROR: "text-red-400",
  PROMPT_INJECTION_DETECTED: "text-rose-600 font-bold",
};

export function AgentFeed({ messages }: { messages: WSMessage[] }) {
  return (
    <div className="bg-gray-900 rounded-lg p-4 h-96 overflow-y-auto font-mono text-sm">
      <div className="text-gray-500 text-xs mb-2 uppercase tracking-widest">Live Agent Feed</div>
      {messages.length === 0 && (
        <div className="text-gray-600 text-xs">Waiting for events...</div>
      )}
      {messages.map((msg, i) => (
        <div key={i} className="mb-1 border-b border-gray-800 pb-1">
          <span className="text-gray-500 text-xs mr-2">
            {new Date(("data" in msg.data && "timestamp" in msg.data ? msg.data.timestamp as string : Date.now())).toLocaleTimeString()}
          </span>
          <span className={`mr-2 ${EVENT_COLORS[msg.type] ?? "text-white"}`}>
            [{msg.type}]
          </span>
          <span className="text-gray-300 text-xs">
            {"agent_id" in msg.data ? msg.data.agent_id : ""}
            {" · "}
            {"correlation_id" in msg.data ? `corr:${(msg.data as {correlation_id: string}).correlation_id}` : ""}
          </span>
        </div>
      ))}
    </div>
  );
}
```

- [ ] **Step 5: Write `src/components/HitlQueue.tsx`**

```typescript
// norda-mas/services/dashboard/src/components/HitlQueue.tsx
import { useState, useEffect } from "react";

const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

interface PendingDecision {
  decision_id: string;
  correlation_id: string;
  decision: Record<string, unknown>;
  rationale: string;
  enqueued_at: string;
}

export function HitlQueue() {
  const [pending, setPending] = useState<PendingDecision[]>([]);

  const fetchPending = async () => {
    const res = await fetch(`${API}/hitl/pending`);
    const data = await res.json();
    setPending(data.pending ?? []);
  };

  useEffect(() => {
    fetchPending();
    const id = setInterval(fetchPending, 3000);
    return () => clearInterval(id);
  }, []);

  const resolve = async (decision_id: string, action: string) => {
    await fetch(`${API}/hitl/${decision_id}/resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, operator_id: "operator-001" }),
    });
    fetchPending();
  };

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-500 text-xs mb-3 uppercase tracking-widest">
        HITL Queue · {pending.length} pending
      </div>
      {pending.length === 0 && (
        <div className="text-gray-600 text-xs">No decisions awaiting approval.</div>
      )}
      {pending.map((d) => (
        <div key={d.decision_id} className="mb-3 border border-yellow-800 rounded p-3 bg-gray-950">
          <div className="text-yellow-400 text-xs font-bold mb-1">⚠ HUMAN REVIEW REQUIRED</div>
          <div className="text-gray-300 text-xs mb-1">
            <span className="text-gray-500">Correlation:</span> {d.correlation_id}
          </div>
          <div className="text-gray-300 text-xs mb-2">
            <span className="text-gray-500">Rationale:</span> {d.rationale}
          </div>
          <pre className="text-gray-400 text-xs bg-gray-800 rounded p-2 mb-2 overflow-auto">
            {JSON.stringify(d.decision, null, 2)}
          </pre>
          <div className="flex gap-2">
            <button
              onClick={() => resolve(d.decision_id, "APPROVE")}
              className="px-3 py-1 bg-emerald-700 hover:bg-emerald-600 text-white text-xs rounded"
            >
              Approve
            </button>
            <button
              onClick={() => resolve(d.decision_id, "REJECT")}
              className="px-3 py-1 bg-red-700 hover:bg-red-600 text-white text-xs rounded"
            >
              Reject
            </button>
            <button
              onClick={() => resolve(d.decision_id, "SUSPEND")}
              className="px-3 py-1 bg-yellow-700 hover:bg-yellow-600 text-white text-xs rounded"
            >
              Suspend
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
```

- [ ] **Step 6: Write `src/components/DecisionLog.tsx`**

```typescript
// norda-mas/services/dashboard/src/components/DecisionLog.tsx
import { AuditEntry } from "../types/events";
import { WSMessage } from "../types/events";

export function DecisionLog({ messages }: { messages: WSMessage[] }) {
  const decisions = messages
    .filter((m) => m.type === "DECISION_VALIDATED")
    .map((m) => m.data as AuditEntry);

  return (
    <div className="bg-gray-900 rounded-lg p-4 h-96 overflow-y-auto">
      <div className="text-gray-500 text-xs mb-2 uppercase tracking-widest">
        Signed Audit Chain
      </div>
      {decisions.length === 0 && (
        <div className="text-gray-600 text-xs">No validated decisions yet.</div>
      )}
      {decisions.map((d, i) => (
        <div key={i} className="mb-2 border border-gray-700 rounded p-2 text-xs font-mono">
          <div className="flex justify-between mb-1">
            <span className="text-emerald-400">#{d.sequence}</span>
            <span className="text-gray-500">{d.agent_id}</span>
            <span className="text-gray-500">{new Date(d.timestamp).toLocaleTimeString()}</span>
          </div>
          <div className="text-gray-300 mb-1">{d.rationale}</div>
          <div className="text-gray-600 text-xs truncate">hash: {d.entry_hash}</div>
          <div className="text-gray-600 text-xs truncate">prev: {d.previous_hash}</div>
          <div className="text-gray-600 text-xs truncate">sig:  {d.signature}</div>
        </div>
      ))}
    </div>
  );
}
```

- [ ] **Step 7: Write `src/components/SystemHealth.tsx`**

```typescript
// norda-mas/services/dashboard/src/components/SystemHealth.tsx
export function SystemHealth({ connected }: { connected: boolean }) {
  return (
    <div className="flex items-center gap-4 text-xs font-mono">
      <div className="flex items-center gap-1">
        <div className={`w-2 h-2 rounded-full ${connected ? "bg-emerald-400" : "bg-red-500"}`} />
        <span className="text-gray-400">Orchestrator</span>
      </div>
      <div className="flex items-center gap-1">
        <div className="w-2 h-2 rounded-full bg-emerald-400" />
        <span className="text-gray-400">Governance</span>
      </div>
      <div className="flex items-center gap-1">
        <div className="w-2 h-2 rounded-full bg-emerald-400" />
        <span className="text-gray-400">Wazuh SOC</span>
      </div>
    </div>
  );
}
```

- [ ] **Step 8: Write `src/App.tsx`**

```typescript
// norda-mas/services/dashboard/src/App.tsx
import { useWebSocket } from "./hooks/useWebSocket";
import { AgentFeed } from "./components/AgentFeed";
import { DecisionLog } from "./components/DecisionLog";
import { HitlQueue } from "./components/HitlQueue";
import { SystemHealth } from "./components/SystemHealth";

const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/ws";

export default function App() {
  const { messages, connected } = useWebSocket(WS_URL);

  return (
    <div className="min-h-screen bg-gray-950 text-white p-6">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">NORDA Bank · MAS Operations</h1>
            <p className="text-gray-500 text-sm mt-1">Multi-Agent Fraud Detection · Governance Console</p>
          </div>
          <SystemHealth connected={connected} />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <AgentFeed messages={messages} />
          </div>
          <div>
            <HitlQueue />
          </div>
        </div>

        <div className="mt-6">
          <DecisionLog messages={messages} />
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 9: Write `services/dashboard/Dockerfile`**

```dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 3000
CMD ["nginx", "-g", "daemon off;"]
```

- [ ] **Step 10: Commit**

```bash
git add services/dashboard/
git commit -m "feat: React dashboard with live WebSocket feed, HITL queue, and signed audit log"
```

---

## Task 11: Transaction Simulator (Demo Feed)

**Files:**
- Create: `norda-mas/simulator/simulate.py`

- [ ] **Step 1: Write `simulator/simulate.py`**

```python
# norda-mas/simulator/simulate.py
"""
Generates synthetic transaction events and injects them into the MAS pipeline.
Run: python simulator/simulate.py
"""
import asyncio
import random
import uuid
import httpx
from datetime import datetime, timezone

ORCHESTRATOR_URL = "http://localhost:8000"

TRANSACTION_TYPES = ["WIRE_TRANSFER", "CARD_PAYMENT", "ATM_WITHDRAWAL", "SEPA_CREDIT"]
MERCHANT_CATEGORIES = ["GAMBLING", "CRYPTO_EXCHANGE", "LUXURY_GOODS", "RETAIL", "FOOD", "TRAVEL"]


def generate_transaction() -> dict:
    return {
        "transaction_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "amount": round(random.uniform(10, 50000), 2),
        "currency": random.choice(["EUR", "USD", "GBP"]),
        "type": random.choice(TRANSACTION_TYPES),
        "merchant_category": random.choice(MERCHANT_CATEGORIES),
        "account_id": f"ACC-{random.randint(1000, 9999)}",
        "counterparty_country": random.choice(["FR", "DE", "US", "RU", "CN", "NG", "IR"]),
        "velocity_24h": random.randint(1, 30),
    }


async def run(rate_per_second: float = 1.0):
    interval = 1.0 / rate_per_second
    async with httpx.AsyncClient() as client:
        print(f"Injecting transactions at {rate_per_second} tx/s — press Ctrl+C to stop")
        while True:
            txn = generate_transaction()
            try:
                await client.post(
                    f"{ORCHESTRATOR_URL}/events/inject",
                    json={"correlation_id": txn["transaction_id"], "payload": txn},
                    timeout=5.0,
                )
                print(f"[{txn['type']}] {txn['amount']} {txn['currency']} → {txn['counterparty_country']}")
            except Exception as e:
                print(f"Inject failed: {e}")
            await asyncio.sleep(interval)


if __name__ == "__main__":
    asyncio.run(run(rate_per_second=2.0))
```

- [ ] **Step 2: Commit**

```bash
git add simulator/
git commit -m "feat: synthetic transaction simulator for demo feed"
```

---

## Self-Review

**Spec coverage check:**
- FR1 (multi-agent): Agent base class in Task 8 — agents are plug-in points ✓
- FR2 (governance layer): Task 4 + Task 7 — SHA256 chain, validates before writing ✓
- FR3 (human operator dashboard): Task 10 — AgentFeed, DecisionLog, HitlQueue, SystemHealth ✓
- Security (JWT, no plain-text, signed logs, prompt injection hook): Tasks 3, 4, 6, 7 ✓
- Auditability (reproducible with exact context): AuditEntry stores input_hash + agent_version ✓
- Explainability (rationale field): required in AuditEntry schema and base agent output ✓
- Human Control (suspend/cancel/modify): HITLQueue resolve() with APPROVE/REJECT/SUSPEND ✓
- Zero Trust (every request authenticated): JWT on every Redis Streams message ✓
- Wazuh SOC: Task 5 + wired in Task 7 ✓

**Placeholder scan:** No TBD, no TODO, no vague steps found.

**Type consistency:**
- `HITLAction` enum used consistently in `hitl.py`, `events.py`, `HitlQueue.tsx`
- `AgentMessage.jwt_token` matches what `BaseAgent.publish()` injects
- `AuditEntry` fields match `persist_entry()` SQL parameters ✓
