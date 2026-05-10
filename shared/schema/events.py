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
