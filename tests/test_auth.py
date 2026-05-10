import pytest
from services.orchestrator.auth import sign_message, verify_message, AuthError


def test_sign_and_verify_roundtrip():
    secret = "test-secret-32-chars-minimum-ok!"
    payload = {"agent_id": "detection-v1", "correlation_id": "txn-123"}
    token = sign_message(payload, secret, ttl_seconds=30)
    decoded = verify_message(token, secret)
    assert decoded["agent_id"] == "detection-v1"
    assert decoded["correlation_id"] == "txn-123"


def test_tampered_token_rejected():
    secret = "test-secret-32-chars-minimum-ok!"
    payload = {"agent_id": "detection-v1"}
    token = sign_message(payload, secret, ttl_seconds=30)
    tampered = token[:-5] + "XXXXX"
    with pytest.raises(AuthError):
        verify_message(tampered, secret)


def test_wrong_secret_rejected():
    token = sign_message({"agent_id": "x"}, "secret-one-32-chars-minimum-xxx!", ttl_seconds=30)
    with pytest.raises(AuthError):
        verify_message(token, "secret-two-32-chars-minimum-xxx!")


def test_expired_token_rejected():
    token = sign_message({"agent_id": "x"}, "test-secret-32-chars-minimum-ok!", ttl_seconds=-1)
    with pytest.raises(AuthError):
        verify_message(token, "test-secret-32-chars-minimum-ok!")
