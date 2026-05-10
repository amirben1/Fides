# norda-mas/services/governance/main.py
import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import asyncpg
import redis.asyncio as aioredis

from services.governance.chain import ChainSigner
from services.governance.injection_guard import detect_injection
from services.governance.wazuh import WazuhBridge
from services.orchestrator.auth import verify_message, AuthError
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

    # Injection guard — quarantine before chaining
    is_injection, inj_reason, inj_technique = detect_injection(msg.payload)
    if is_injection:
        logger.warning("INJECTION DETECTED from %s: %s", msg.agent_id, inj_reason)
        alert = json.dumps({
            "type": "PROMPT_INJECTION_DETECTED",
            "agent_id": msg.agent_id,
            "correlation_id": msg.correlation_id,
            "reason": inj_reason,
            "technique": inj_technique,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        await redis_client.xadd(DECISIONS_STREAM, {"data": alert})
        if wazuh:
            await wazuh.send_event(
                "PROMPT_INJECTION_DETECTED",
                {"reason": inj_reason, "technique": inj_technique},
                msg.correlation_id,
            )
        return  # never chain injected payloads

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

    signed_entry = entry.model_dump_json()
    await redis_client.xadd(DECISIONS_STREAM, {"data": signed_entry})

    if wazuh:
        await wazuh.send_event(msg.event_type.value, msg.payload, msg.correlation_id)


async def main() -> None:
    global wazuh
    if WAZUH_API_URL:
        wazuh = WazuhBridge(WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD, verify_ssl=False)

    redis_client = await aioredis.from_url(REDIS_URL)
    db_pool = await asyncpg.create_pool(DATABASE_URL)

    try:
        await redis_client.xgroup_create(EVENTS_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
    except Exception:
        pass

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
