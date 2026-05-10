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
