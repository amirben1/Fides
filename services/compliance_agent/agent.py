# norda-mas/services/compliance_agent/agent.py
import asyncio
import os
from typing import Any

from services.agent_base.base_agent import BaseAgent

OFAC_SANCTIONED = {"IR", "KP", "SY", "CU", "VE", "BY", "RU"}
EU_SANCTIONED = {"IR", "KP", "SY", "BY", "RU", "LY"}
ALL_SANCTIONED = OFAC_SANCTIONED | EU_SANCTIONED

AML_HIGH_RISK_CATEGORIES = {"GAMBLING", "CRYPTO_EXCHANGE"}
PEP_ACCOUNT_PREFIXES = ("ACC-9", "ACC-8")  # Simulated PEP accounts for demo


class ComplianceAgent(BaseAgent):
    AGENT_ID = os.environ.get("AGENT_ID", "compliance-agent-v1")
    AGENT_VERSION = "1.0.0"

    async def process(self, payload: dict[str, Any]) -> dict[str, Any]:
        country = str(payload.get("counterparty_country", ""))
        category = str(payload.get("merchant_category", ""))
        amount = float(payload.get("amount", 0))
        velocity = int(payload.get("velocity_24h", 0))
        account_id = str(payload.get("account_id", ""))

        aml_flags: list[str] = []
        sanctions_hit = False
        sanctions_list: list[str] = []
        pep_hit = False

        # Sanctions screening
        if country in OFAC_SANCTIONED:
            sanctions_hit = True
            sanctions_list.append("OFAC SDN")
        if country in EU_SANCTIONED:
            sanctions_hit = True
            if "EU Consolidated Sanctions" not in sanctions_list:
                sanctions_list.append("EU Consolidated Sanctions")

        # PEP check (simulated — demo purposes)
        if any(account_id.startswith(prefix) for prefix in PEP_ACCOUNT_PREFIXES):
            pep_hit = True
            aml_flags.append("PEP_ACCOUNT_IDENTIFIED")

        # AML typology detection
        if category in AML_HIGH_RISK_CATEGORIES and amount > 10_000:
            aml_flags.append("AML_TYPOLOGY:HIGH_RISK_SECTOR_LARGE_AMOUNT")

        if velocity > 15 and amount > 5_000:
            aml_flags.append("AML_TYPOLOGY:STRUCTURING_PATTERN")

        if country in ALL_SANCTIONED and category == "CRYPTO_EXCHANGE":
            aml_flags.append("AML_TYPOLOGY:SANCTIONS_EVASION_VIA_CRYPTO")

        # KYC status determination
        if sanctions_hit:
            kyc_status = "BLOCKED"
        elif pep_hit:
            kyc_status = "ENHANCED_DUE_DILIGENCE"
        elif aml_flags:
            kyc_status = "REVIEW_REQUIRED"
        else:
            kyc_status = "CLEAR"

        reasons: list[str] = []
        if sanctions_hit:
            reasons.append(f"Sanctions match: {', '.join(sanctions_list)} — country {country}")
        if pep_hit:
            reasons.append("Politically Exposed Person account identified")
        reasons.extend(aml_flags)

        rationale = (
            f"KYC status: {kyc_status}. "
            + (f"Compliance issues: {'; '.join(reasons)}." if reasons else "No compliance flags raised.")
        )

        return {
            "sanctions_hit": sanctions_hit,
            "sanctions_list": sanctions_list,
            "pep_hit": pep_hit,
            "aml_flags": aml_flags,
            "kyc_status": kyc_status,
            "rationale": rationale,
            "account_id": account_id,
            "transaction_id": payload.get("transaction_id", ""),
        }

    def requires_hitl(self, output: dict[str, Any]) -> bool:
        return bool(output.get("sanctions_hit")) or bool(output.get("pep_hit"))


if __name__ == "__main__":
    asyncio.run(ComplianceAgent().run())
