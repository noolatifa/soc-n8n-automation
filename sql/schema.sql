-- ===========================================================
-- SOC Blue Team — Database Schema (socdb)
-- ===========================================================
-- This schema defines the core traceability tables managed by the
-- Blue Team orchestration layer (n8n).

-- 1. Table: alerts
-- Stores the history of every analyzed alert.
CREATE TABLE IF NOT EXISTS alerts (
    id                SERIAL PRIMARY KEY,
    timestamp         TIMESTAMPTZ DEFAULT NOW(),
    src_ip            VARCHAR(64),
    description       TEXT,
    rule_level        INTEGER,
    ai_classification VARCHAR(64),
    ai_attack_type    VARCHAR(256),
    ai_confidence     FLOAT,
    mitre_tactic      VARCHAR(128),
    action_executed   TEXT,
    analysis_context  TEXT,
    reasoning         TEXT,
    correlation_id    VARCHAR(64) UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);


-- 2. Table: pending_actions
-- Tracks the automated actions triggered by the platform.
CREATE TABLE IF NOT EXISTS pending_actions (
    id               SERIAL PRIMARY KEY,
    correlation_id   VARCHAR(64),
    action_type      VARCHAR(64),      -- BLOCK_IP, BLOCK_PORT, ISOLATE_ENDPOINT
    target           VARCHAR(128),     -- IP alone, or IP:port
    rule_id          VARCHAR(64),
    reason           TEXT,
    status           VARCHAR(32) DEFAULT 'pending', -- pending, confirmed, rolled_back
    hive_case_id     VARCHAR(64),
    ai_confidence    INTEGER,
    rollback_reason  TEXT,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    confirmed_at     TIMESTAMPTZ,
    rolled_back_at   TIMESTAMPTZ,

    -- Crucial constraint: allows multiple DIFFERENT action types for the same alert
    -- (e.g., BLOCK_IP + BLOCK_PORT), but strictly forbids duplicates of the SAME 
    -- action type for the same alert. (Fixes n8n retry issues).
    CONSTRAINT uq_alert_action UNIQUE (correlation_id, action_type)
);

CREATE INDEX IF NOT EXISTS idx_pending_correlation ON pending_actions(correlation_id);
CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_actions(status);