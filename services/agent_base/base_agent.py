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
