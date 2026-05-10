-- norda-mas/infra/postgres/init.sql
CREATE TABLE IF NOT EXISTS audit_chain (
    id              UUID PRIMARY KEY,
    sequence        BIGINT NOT NULL UNIQUE,
    timestamp       TIMESTAMPTZ NOT NULL,
    agent_id        TEXT NOT NULL,
    agent_version   TEXT NOT NULL,
    correlation_id  TEXT NOT NULL,
    decision_type   TEXT NOT NULL,
    input_hash      TEXT NOT NULL,
    decision        JSONB NOT NULL,
    rationale       TEXT NOT NULL,
    previous_hash   TEXT NOT NULL,
    entry_hash      TEXT NOT NULL,
    signature       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_chain_correlation ON audit_chain(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_chain_sequence ON audit_chain(sequence);

CREATE TABLE IF NOT EXISTS hitl_queue (
    id              UUID PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL,
    decision_id     TEXT NOT NULL,
    correlation_id  TEXT NOT NULL,
    decision        JSONB NOT NULL,
    rationale       TEXT NOT NULL,
    action          TEXT,
    operator_id     TEXT,
    resolved_at     TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'PENDING'
);

CREATE INDEX IF NOT EXISTS idx_hitl_status ON hitl_queue(status);
