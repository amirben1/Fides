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

    def enqueue(
        self,
        *,
        decision_id: str,
        correlation_id: str,
        decision: dict[str, Any],
        rationale: str,
        explanation: dict[str, Any] | None = None,
    ) -> None:
        self._pending[decision_id] = {
            "decision_id": decision_id,
            "correlation_id": correlation_id,
            "decision": decision,
            "rationale": rationale,
            "explanation": explanation,
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
