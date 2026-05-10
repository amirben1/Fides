# norda-mas/tests/test_detection_agent.py
import pytest
from services.detection_agent.agent import DetectionAgent, score_transaction, risk_tier


def test_sanctioned_country_scores_high():
    score, flags = score_transaction({
        "counterparty_country": "IR", "amount": 1000,
        "velocity_24h": 1, "merchant_category": "RETAIL", "type": "WIRE_TRANSFER",
    })
    assert score >= 0.6
    assert any("SANCTIONED" in f for f in flags)


def test_clean_transaction_scores_low():
    score, flags = score_transaction({
        "counterparty_country": "FR", "amount": 100,
        "velocity_24h": 1, "merchant_category": "FOOD", "type": "CARD_PAYMENT",
    })
    assert score < 0.3
    assert flags == []


def test_critical_amount_flagged():
    score, flags = score_transaction({
        "counterparty_country": "FR", "amount": 80000,
        "velocity_24h": 1, "merchant_category": "RETAIL", "type": "WIRE_TRANSFER",
    })
    assert any("CRITICAL_AMOUNT" in f for f in flags)


def test_high_velocity_flagged():
    score, flags = score_transaction({
        "counterparty_country": "FR", "amount": 100,
        "velocity_24h": 25, "merchant_category": "FOOD", "type": "CARD_PAYMENT",
    })
    assert any("VELOCITY" in f for f in flags)


def test_risk_tiers():
    assert risk_tier(0.0) == "LOW"
    assert risk_tier(0.3) == "MEDIUM"
    assert risk_tier(0.5) == "HIGH"
    assert risk_tier(0.7) == "CRITICAL"
    assert risk_tier(1.0) == "CRITICAL"


@pytest.mark.asyncio
async def test_process_returns_required_fields():
    agent = DetectionAgent()
    result = await agent.process({
        "counterparty_country": "FR", "amount": 500,
        "velocity_24h": 3, "merchant_category": "RETAIL", "type": "CARD_PAYMENT",
    })
    assert "risk_score" in result
    assert "risk_tier" in result
    assert "flags" in result
    assert "rationale" in result
    assert isinstance(result["flags"], list)


@pytest.mark.asyncio
async def test_requires_hitl_for_critical():
    agent = DetectionAgent()
    result = await agent.process({
        "counterparty_country": "IR", "amount": 50000,
        "velocity_24h": 25, "merchant_category": "CRYPTO_EXCHANGE", "type": "WIRE_TRANSFER",
    })
    assert result["risk_tier"] == "CRITICAL"
    assert agent.requires_hitl(result) is True


@pytest.mark.asyncio
async def test_does_not_require_hitl_for_low_risk():
    agent = DetectionAgent()
    result = await agent.process({
        "counterparty_country": "FR", "amount": 50,
        "velocity_24h": 1, "merchant_category": "FOOD", "type": "CARD_PAYMENT",
    })
    assert agent.requires_hitl(result) is False
