# norda-mas/tests/test_explainer.py
import pytest
from services.orchestrator.explainer import generate_explanation


def test_high_risk_country_detected():
    payload = {"counterparty_country": "IR", "amount": 1000, "velocity_24h": 5, "merchant_category": "RETAIL"}
    result = generate_explanation(payload)
    assert any("IR" in r for r in result["why_flagged"])
    assert "AML" in result["regulation"]
    assert result["risk_level"] in ("HIGH", "CRITICAL")


def test_high_amount_flagged():
    payload = {"counterparty_country": "FR", "amount": 80000, "velocity_24h": 3, "merchant_category": "RETAIL"}
    result = generate_explanation(payload)
    assert any("80,000" in r or "80000" in r for r in result["why_flagged"])
    assert result["risk_level"] == "CRITICAL"


def test_high_velocity_flagged():
    payload = {"counterparty_country": "FR", "amount": 500, "velocity_24h": 25, "merchant_category": "FOOD"}
    result = generate_explanation(payload)
    assert any("25" in r for r in result["why_flagged"])


def test_clean_transaction_low_risk():
    payload = {"counterparty_country": "FR", "amount": 50, "velocity_24h": 2, "merchant_category": "FOOD"}
    result = generate_explanation(payload)
    assert result["risk_level"] == "LOW"
    assert len(result["why_flagged"]) >= 1


def test_explanation_always_has_required_keys():
    result = generate_explanation({})
    assert "why_flagged" in result
    assert "regulation" in result
    assert "recommended_action" in result
    assert "risk_level" in result
    assert isinstance(result["why_flagged"], list)
