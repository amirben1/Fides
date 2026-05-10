from typing import Any

_TECHNIQUES: dict[str, dict[str, Any]] = {
    "AML0043": {"name": "Prompt Injection", "attempts": 0, "blocked": 0},
    "AML0054": {"name": "LLM Jailbreak / Auth Bypass", "attempts": 0, "blocked": 0},
    "AML0015": {"name": "Evade ML Model", "attempts": 0, "blocked": 0},
    "AML0002": {"name": "Backdoor ML Model", "attempts": 0, "blocked": 0},
}

_EVENT_MAP: dict[str, tuple[str, bool, str]] = {
    "PROMPT_INJECTION_DETECTED": ("AML0043", True, "security"),
    "AGENT_ERROR": ("AML0054", False, "operational"),
    "HITL_REQUIRED": ("AML0015", False, "monitoring"),
}


class AtlasTracker:
    def __init__(self) -> None:
        self._counts: dict[str, dict[str, int]] = {
            tid: {"attempts": 0, "blocked": 0} for tid in _TECHNIQUES
        }
        self._status_hints: dict[str, str] = {tid: "monitoring" for tid in _TECHNIQUES}

    def record(self, event_type: str, payload: dict[str, Any]) -> None:
        mapping = _EVENT_MAP.get(event_type)
        if mapping is None:
            return
        technique_id, is_blocked, status_hint = mapping
        self._counts[technique_id]["attempts"] += 1
        self._status_hints[technique_id] = status_hint
        if is_blocked:
            self._counts[technique_id]["blocked"] += 1

    def get_threats(self) -> list[dict[str, Any]]:
        result = []
        for tid, meta in _TECHNIQUES.items():
            counts = self._counts[tid]
            attempts = counts["attempts"]
            blocked = counts["blocked"]
            status_hint = self._status_hints[tid]

            if attempts == 0:
                status = "monitoring"
            elif status_hint == "monitoring":
                status = "monitoring"
            elif blocked == attempts:
                status = "blocked"
            else:
                status = "active"

            result.append({
                "technique_id": tid,
                "name": meta["name"],
                "attempts": attempts,
                "blocked": blocked,
                "status": status,
            })
        return result
