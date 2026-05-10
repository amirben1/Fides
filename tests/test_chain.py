import pytest
from services.governance.chain import ChainSigner, ChainVerificationError


GOVERNANCE_SECRET = "test-governance-secret-32-chars!!"


@pytest.fixture
def signer():
    return ChainSigner(secret=GOVERNANCE_SECRET)


def test_first_entry_has_genesis_previous_hash(signer):
    entry = signer.build_entry(
        sequence=1,
        agent_id="detection-v1",
        agent_version="1.0.0",
        correlation_id="txn-001",
        decision_type="RISK_ASSESSMENT",
        input_payload={"amount": 5000},
        decision={"risk_score": 0.9},
        rationale="High velocity",
        previous_hash="0" * 64,
    )
    assert entry.previous_hash == "0" * 64
    assert len(entry.entry_hash) == 64
    assert len(entry.signature) > 0


def test_chain_links_correctly(signer):
    entry1 = signer.build_entry(
        sequence=1, agent_id="a", agent_version="1.0", correlation_id="c1",
        decision_type="T", input_payload={}, decision={}, rationale="r",
        previous_hash="0" * 64,
    )
    entry2 = signer.build_entry(
        sequence=2, agent_id="a", agent_version="1.0", correlation_id="c2",
        decision_type="T", input_payload={}, decision={}, rationale="r",
        previous_hash=entry1.entry_hash,
    )
    assert entry2.previous_hash == entry1.entry_hash


def test_tampered_entry_fails_verification(signer):
    entry = signer.build_entry(
        sequence=1, agent_id="a", agent_version="1.0", correlation_id="c1",
        decision_type="T", input_payload={}, decision={}, rationale="r",
        previous_hash="0" * 64,
    )
    entry.rationale = "TAMPERED"
    with pytest.raises(ChainVerificationError):
        signer.verify_entry(entry)


def test_valid_entry_passes_verification(signer):
    entry = signer.build_entry(
        sequence=1, agent_id="a", agent_version="1.0", correlation_id="c1",
        decision_type="T", input_payload={}, decision={}, rationale="r",
        previous_hash="0" * 64,
    )
    signer.verify_entry(entry)  # must not raise
