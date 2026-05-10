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
