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
