# norda-mas/services/detection_agent/agent.py
import asyncio
import os
from typing import Any

from services.agent_base.base_agent import BaseAgent

SANCTIONED_COUNTRIES = {"IR", "KP", "SY", "CU", "VE"}
HIGH_RISK_COUNTRIES = {"RU", "NG", "BY", "UA", "MM", "AF", "IQ", "LY", "SO", "YE"}
HIGH_RISK_CATEGORIES = {"GAMBLING", "CRYPTO_EXCHANGE"}

VELOCITY_HIGH = 20
VELOCITY_MEDIUM = 15
AMOUNT_CRITICAL = 75_000
AMOUNT_HIGH = 30_000


def score_transaction(payload: dict[str, Any]) -> tuple[float, list[str]]:
    points = 0
    flags: list[str] = []

    country = str(payload.get("counterparty_country", ""))
    amount = float(payload.get("amount", 0))
    velocity = int(payload.get("velocity_24h", 0))
    category = str(payload.get("merchant_category", ""))
    txn_type = str(payload.get("type", ""))

    if country in SANCTIONED_COUNTRIES:
        points += 60
        flags.append(f"SANCTIONED_COUNTRY:{country}")
    elif country in HIGH_RISK_COUNTRIES:
        points += 35
        flags.append(f"HIGH_RISK_COUNTRY:{country}")

    if amount >= AMOUNT_CRITICAL:
        points += 30
        flags.append(f"CRITICAL_AMOUNT:{amount:.0f}")
    elif amount >= AMOUNT_HIGH:
        points += 15
        flags.append(f"HIGH_AMOUNT:{amount:.0f}")

    if velocity >= VELOCITY_HIGH:
        points += 25
        flags.append(f"HIGH_VELOCITY:{velocity}")
    elif velocity >= VELOCITY_MEDIUM:
        points += 15
        flags.append(f"ELEVATED_VELOCITY:{velocity}")

    if category in HIGH_RISK_CATEGORIES:
        points += 20
        flags.append(f"HIGH_RISK_CATEGORY:{category}")

    if txn_type == "WIRE_TRANSFER" and country in (SANCTIONED_COUNTRIES | HIGH_RISK_COUNTRIES):
        points += 10
        flags.append("WIRE_TO_HIGH_RISK")

    return min(points / 100.0, 1.0), flags


def risk_tier(score: float) -> str:
    if score >= 0.7:
        return "CRITICAL"
    elif score >= 0.5:
        return "HIGH"
    elif score >= 0.3:
        return "MEDIUM"
    return "LOW"


_FLAG_DESCRIPTIONS: dict[str, str] = {
    "SANCTIONED_COUNTRY": "counterparty in OFAC/EU sanctioned jurisdiction",
    "HIGH_RISK_COUNTRY": "counterparty in FATF high-risk jurisdiction",
    "CRITICAL_AMOUNT": "transaction exceeds critical amount threshold",
    "HIGH_AMOUNT": "transaction exceeds standard review threshold",
    "HIGH_VELOCITY": "account velocity significantly exceeds threshold",
    "ELEVATED_VELOCITY": "account velocity above normal threshold",
    "HIGH_RISK_CATEGORY": "merchant category requires enhanced due diligence",
    "WIRE_TO_HIGH_RISK": "wire transfer to high-risk jurisdiction",
}


class DetectionAgent(BaseAgent):
    AGENT_ID = os.environ.get("AGENT_ID", "detection-agent-v1")
    AGENT_VERSION = "1.0.0"

    async def process(self, payload: dict[str, Any]) -> dict[str, Any]:
        risk_score, flags = score_transaction(payload)
        tier = risk_tier(risk_score)

        reasons = [
            _FLAG_DESCRIPTIONS.get(f.split(":")[0], f)
            for f in flags
        ]
        rationale = (
            f"Risk score {risk_score:.2f} [{tier}]. "
            + (f"Triggered: {'; '.join(reasons)}." if reasons else "No specific risk flags detected.")
        )

        return {
            "risk_score": risk_score,
            "risk_tier": tier,
            "flags": flags,
            "rationale": rationale,
            "transaction_id": payload.get("transaction_id", ""),
            "account_id": payload.get("account_id", ""),
        }

    def requires_hitl(self, output: dict[str, Any]) -> bool:
        return float(output.get("risk_score", 0)) >= 0.7


if __name__ == "__main__":
    asyncio.run(DetectionAgent().run())
