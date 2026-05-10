import pytest
from services.orchestrator.atlas import AtlasTracker


@pytest.fixture
def tracker():
    return AtlasTracker()


def test_initial_state_has_all_techniques(tracker):
    threats = tracker.get_threats()
    ids = [t["technique_id"] for t in threats]
    assert "AML0043" in ids
    assert "AML0015" in ids
    assert "AML0054" in ids
    assert "AML0002" in ids


def test_prompt_injection_increments_blocked(tracker):
    tracker.record("PROMPT_INJECTION_DETECTED", {"technique": "AML0043"})
    threats = tracker.get_threats()
    aml0043 = next(t for t in threats if t["technique_id"] == "AML0043")
    assert aml0043["blocked"] == 1
    assert aml0043["attempts"] == 1
    assert aml0043["status"] == "blocked"


def test_agent_error_increments_attempts(tracker):
    tracker.record("AGENT_ERROR", {"reason": "auth_failure"})
    threats = tracker.get_threats()
    aml0054 = next(t for t in threats if t["technique_id"] == "AML0054")
    assert aml0054["attempts"] == 1
    assert aml0054["blocked"] == 0
    assert aml0054["status"] == "active"


def test_hitl_required_increments_monitoring(tracker):
    tracker.record("HITL_REQUIRED", {})
    threats = tracker.get_threats()
    aml0015 = next(t for t in threats if t["technique_id"] == "AML0015")
    assert aml0015["attempts"] == 1
    assert aml0015["status"] == "monitoring"


def test_unknown_event_ignored(tracker):
    tracker.record("TRANSACTION_RECEIVED", {})
    threats = tracker.get_threats()
    total_attempts = sum(t["attempts"] for t in threats)
    assert total_attempts == 0
