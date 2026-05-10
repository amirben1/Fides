import logging
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "HITL_REQUIRED": 12,
    "PROMPT_INJECTION_DETECTED": 15,
    "DECISION_VALIDATED": 5,
    "AGENT_ERROR": 10,
}


class WazuhBridge:
    def __init__(self, api_url: str, user: str, password: str, verify_ssl: bool = False) -> None:
        self._api_url = api_url.rstrip("/")
        self._auth = (user, password)
        self._verify_ssl = verify_ssl
        self._token: str | None = None

    async def _get_token(self, client: httpx.AsyncClient) -> str:
        resp = await client.post(
            f"{self._api_url}/security/user/authenticate",
            auth=self._auth,
            verify=self._verify_ssl,
        )
        resp.raise_for_status()
        return resp.json()["data"]["token"]

    async def send_event(self, event_type: str, payload: dict[str, Any], correlation_id: str) -> None:
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {
                "level": SEVERITY_MAP.get(event_type, 5),
                "description": f"NORDA MAS: {event_type}",
                "id": "100001",
            },
            "agent": {"name": "norda-mas-governance"},
            "data": {
                "event_type": event_type,
                "correlation_id": correlation_id,
                **payload,
            },
        }
        async with httpx.AsyncClient(verify=self._verify_ssl) as client:
            try:
                if not self._token:
                    self._token = await self._get_token(client)
                resp = await client.post(
                    f"{self._api_url}/events",
                    json={"events": [alert]},
                    headers={"Authorization": f"Bearer {self._token}"},
                    verify=self._verify_ssl,
                )
                resp.raise_for_status()
            except (httpx.HTTPError, httpx.RequestError) as e:
                logger.error("Wazuh send failed: %s", e)
                self._token = None  # force re-auth on next call
