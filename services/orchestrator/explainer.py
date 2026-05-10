# norda-mas/services/orchestrator/explainer.py
from typing import Any

HIGH_RISK_COUNTRIES = {"RU", "NG", "IR", "KP", "BY", "CU", "VE", "SY"}
HIGH_RISK_CATEGORIES = {"GAMBLING", "CRYPTO_EXCHANGE"}
VELOCITY_THRESHOLD = 15
AMOUNT_HIGH = 30_000
AMOUNT_CRITICAL = 75_000


def generate_explanation(payload: dict[str, Any]) -> dict[str, Any]:
    country = payload.get("counterparty_country", "")
    amount = float(payload.get("amount", 0))
    velocity = int(payload.get("velocity_24h", 0))
    category = str(payload.get("merchant_category", ""))

    reasons: list[str] = []
    regulations: list[str] = []
    risk_score = 0

    if country in HIGH_RISK_COUNTRIES:
        reasons.append(f"Counterparty located in high-risk jurisdiction: {country} (FATF watchlist)")
        regulations.append("AML 6th Directive Art. 18 — Enhanced Due Diligence required")
        risk_score += 3

    if amount >= AMOUNT_CRITICAL:
        reasons.append(f"Transaction amount €{amount:,.2f} exceeds critical threshold (€{AMOUNT_CRITICAL:,})")
        regulations.append("DORA Art. 11 — Large Exposure Operational Risk")
        risk_score += 6
    elif amount >= AMOUNT_HIGH:
        reasons.append(f"Transaction amount €{amount:,.2f} exceeds standard review threshold (€{AMOUNT_HIGH:,})")
        regulations.append("AML 6th Directive — Suspicious Activity Reporting obligation")
        risk_score += 1

    if velocity > VELOCITY_THRESHOLD:
        reasons.append(
            f"Account velocity: {velocity} transactions in 24h exceeds threshold ({VELOCITY_THRESHOLD})"
        )
        regulations.append("AML 6th Directive — Velocity Pattern Detection")
        risk_score += 2

    if category in HIGH_RISK_CATEGORIES:
        reasons.append(f"Merchant category '{category}' requires Enhanced Due Diligence")
        regulations.append("MiFID II Art. 25 — Suitability Assessment")
        risk_score += 1

    if not reasons:
        reasons.append("Aggregate risk score exceeds automated approval threshold")
        regulations.append("Internal Risk Policy — Manual Review Required")

    if risk_score >= 6:
        risk_level = "CRITICAL"
        action = (
            "Immediately freeze account and escalate to Compliance Officer. "
            "Do not process transaction. File SAR within 24h."
        )
    elif risk_score >= 3:
        risk_level = "HIGH"
        action = "Reject transaction and schedule account review within 24h. File SAR if pattern persists."
    elif risk_score >= 2:
        risk_level = "MEDIUM"
        action = "Request additional verification from account holder before processing."
    else:
        risk_level = "LOW"
        action = "Manual review recommended. Approve with documented rationale."

    return {
        "why_flagged": reasons,
        "regulation": "; ".join(dict.fromkeys(regulations)),
        "recommended_action": action,
        "risk_level": risk_level,
    }
