# norda-mas/simulator/simulate.py
"""
Generates synthetic transaction events and injects them into the MAS pipeline.
Run: python simulator/simulate.py
Env: ORCHESTRATOR_URL (default http://localhost:8000), RATE (default 2.0 tx/s)
"""
import asyncio
import os
import random
import uuid
from datetime import datetime, timezone

import httpx

ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://localhost:8000")
RATE = float(os.environ.get("RATE", "2.0"))

TRANSACTION_TYPES = ["WIRE_TRANSFER", "CARD_PAYMENT", "ATM_WITHDRAWAL", "SEPA_CREDIT"]
MERCHANT_CATEGORIES = ["GAMBLING", "CRYPTO_EXCHANGE", "LUXURY_GOODS", "RETAIL", "FOOD", "TRAVEL"]
COUNTRIES = ["FR", "DE", "US", "RU", "CN", "NG", "IR", "GB", "ES", "IT"]
HIGH_RISK_COUNTRIES = {"RU", "NG", "IR"}


def generate_transaction() -> dict:
    country = random.choice(COUNTRIES)
    amount = round(random.uniform(10, 50000), 2)
    velocity = random.randint(1, 30)
    return {
        "transaction_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "amount": amount,
        "currency": random.choice(["EUR", "USD", "GBP"]),
        "type": random.choice(TRANSACTION_TYPES),
        "merchant_category": random.choice(MERCHANT_CATEGORIES),
        "account_id": f"ACC-{random.randint(1000, 9999)}",
        "counterparty_country": country,
        "velocity_24h": velocity,
        "high_risk": country in HIGH_RISK_COUNTRIES or amount > 30000 or velocity > 20,
    }


async def run(rate_per_second: float = RATE) -> None:
    interval = 1.0 / rate_per_second
    async with httpx.AsyncClient(timeout=5.0) as client:
        print(f"Injecting transactions at {rate_per_second} tx/s to {ORCHESTRATOR_URL} — Ctrl+C to stop")
        while True:
            txn = generate_transaction()
            try:
                resp = await client.post(
                    f"{ORCHESTRATOR_URL}/events/inject",
                    json={"correlation_id": txn["transaction_id"], "payload": txn},
                )
                risk_tag = " [HIGH RISK]" if txn["high_risk"] else ""
                print(f"[{txn['type']}] {txn['amount']} {txn['currency']} → {txn['counterparty_country']}{risk_tag}")
            except httpx.ConnectError:
                print(f"Cannot connect to {ORCHESTRATOR_URL} — is the orchestrator running?")
            except Exception as e:
                print(f"Inject failed: {e}")
            await asyncio.sleep(interval)


if __name__ == "__main__":
    asyncio.run(run())
