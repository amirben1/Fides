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
        if websocket in ws_clients:
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


@app.post("/hitl/{decision_id}/enqueue")
async def enqueue_hitl(decision_id: str, req: dict):
    """Called by governance/agents to add a decision to the HITL queue."""
    hitl_queue.enqueue(
        decision_id=decision_id,
        correlation_id=req.get("correlation_id", ""),
        decision=req.get("decision", {}),
        rationale=req.get("rationale", ""),
    )
    await broadcast({"type": "HITL_REQUIRED", "data": {"decision_id": decision_id, **req}})
    return {"status": "enqueued"}


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
