# norda-mas/tests/conftest.py
"""
Set required environment variables before any agent module is imported,
so tests can run without a live Redis/governance secret.
"""
import os

os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("GOVERNANCE_SECRET", "test-secret")
