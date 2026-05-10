# norda-mas/tests/test_compliance_agent.py
import pytest
from services.compliance_agent.agent import ComplianceAgent


@pytest.mark.asyncio
async def test_sanctioned_country_blocked():
    agent = ComplianceAgent()
    result = await agent.process({
        "counterparty_country": "IR", "amount": 1000,
        "velocity_24h": 1, "merchant_category": "RETAIL", "account_id": "ACC-1234",
    })
    assert result["sanctions_hit"] is True
    assert result["kyc_status"] == "BLOCKED"
    assert agent.requires_hitl(result) is True


@pytest.mark.asyncio
async def test_clean_transaction_clears():
    agent = ComplianceAgent()
    result = await agent.process({
        "counterparty_country": "FR", "amount": 100,
        "velocity_24h": 1, "merchant_category": "FOOD", "account_id": "ACC-1234",
    })
    assert result["sanctions_hit"] is False
    assert result["kyc_status"] == "CLEAR"
    assert agent.requires_hitl(result) is False


@pytest.mark.asyncio
async def test_pep_account_triggers_edd():
    agent = ComplianceAgent()
    result = await agent.process({
        "counterparty_country": "FR", "amount": 100,
        "velocity_24h": 1, "merchant_category": "FOOD", "account_id": "ACC-9001",
    })
    assert result["pep_hit"] is True
    assert result["kyc_status"] == "ENHANCED_DUE_DILIGENCE"
    assert agent.requires_hitl(result) is True


@pytest.mark.asyncio
async def test_aml_pattern_detected():
    agent = ComplianceAgent()
    result = await agent.process({
        "counterparty_country": "FR", "amount": 15000,
        "velocity_24h": 18, "merchant_category": "GAMBLING", "account_id": "ACC-1234",
    })
    assert len(result["aml_flags"]) > 0
    assert result["kyc_status"] == "REVIEW_REQUIRED"


@pytest.mark.asyncio
async def test_sanctions_evasion_via_crypto_flagged():
    agent = ComplianceAgent()
    result = await agent.process({
        "counterparty_country": "IR", "amount": 5000,
        "velocity_24h": 1, "merchant_category": "CRYPTO_EXCHANGE", "account_id": "ACC-1234",
    })
    assert any("CRYPTO" in f for f in result["aml_flags"])
    assert result["sanctions_hit"] is True


@pytest.mark.asyncio
async def test_result_has_required_fields():
    agent = ComplianceAgent()
    result = await agent.process({})
    assert "sanctions_hit" in result
    assert "aml_flags" in result
    assert "kyc_status" in result
    assert "rationale" in result
    assert isinstance(result["aml_flags"], list)
    assert isinstance(result["sanctions_list"], list)
