# 10 — PostgreSQL: Data Model, Traceability & Read-Only Access

> PostgreSQL 16 runs on the **VM SOC** (`pc1-soc`, `100.64.0.11`). It serves a
> dual purpose: it is the internal state database for n8n (workflows, executions,
> credentials) and it hosts the application database **`socdb`**, which is the
> core of the platform's traceability and decision audit.

---

## 1. The `alerts` table

This table stores the history of every analyzed alert. Each row represents a
unique alert identified by its `correlation_id`.

```sql
CREATE TABLE alerts (
    id               SERIAL PRIMARY KEY,
    timestamp        TIMESTAMPTZ DEFAULT NOW(),
    src_ip           VARCHAR(64),
    description      TEXT,
    rule_level       INTEGER,
    ai_classification VARCHAR(64),
    ai_attack_type   VARCHAR(256),
    ai_confidence    FLOAT,
    mitre_tactic     VARCHAR(128),
    action_executed  TEXT,
    analysis_context TEXT,
    reasoning        TEXT,
    correlation_id   VARCHAR(64) UNIQUE
);

CREATE INDEX idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
```

**Key constraint**: `correlation_id` is `UNIQUE`. This prevents the exact same
alert from being processed twice (e.g., in case of a manual replay or a retry
in n8n).

---

## 2. The `pending_actions` table

This table tracks the automated actions triggered by the platform. A single
alert can result in multiple actions (e.g., `BLOCK_IP` and `BLOCK_PORT`
simultaneously).

```sql
CREATE TABLE pending_actions (
    id               SERIAL PRIMARY KEY,
    correlation_id   VARCHAR(64),
    action_type      VARCHAR(64),      -- BLOCK_IP, BLOCK_PORT, etc.
    target           VARCHAR(128),     -- IP alone, or IP:port
    rule_id          VARCHAR(64),
    reason           TEXT,
    status           VARCHAR(32),      -- pending, confirmed, rolled_back
    hive_case_id     VARCHAR(64),
    ai_confidence    INTEGER,
    rollback_reason  TEXT,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    confirmed_at     TIMESTAMPTZ,
    rolled_back_at   TIMESTAMPTZ
);
```

**Key constraint**: A composite unique constraint is applied:

```sql
ALTER TABLE pending_actions 
ADD CONSTRAINT uq_alert_action UNIQUE (correlation_id, action_type);
```

This allows an alert to have *different* types of actions (one `BLOCK_IP` and
one `BLOCK_PORT`), but strictly forbids duplicate actions of the *same* type
for the same alert.

---

## 3. Correlation between tables

The logical link between `alerts` and `pending_actions` is the `correlation_id`.
The typical consultation query used by the platform and the dashboards is:

```sql
SELECT 
    a.correlation_id, a.src_ip, a.rule_level, 
    a.ai_classification, a.ai_confidence,
    p.action_type, p.target, p.status
FROM alerts a
LEFT JOIN pending_actions p ON p.correlation_id = a.correlation_id
ORDER BY a.id DESC LIMIT 10;
```

During validation (Scenario 5), this query successfully returned two confirmed
actions for a single critical alert:

```text
 correlation_id        | src_ip        | action_type | target          | status
-----------------------+---------------+-------------+-----------------+-----------
 1787081965919-jzup... | 198.51.100.55 | BLOCK_IP    | 198.51.100.55   | confirmed
 1787081965919-jzup... | 198.51.100.55 | BLOCK_PORT  | 198.51.100.55:22| confirmed
```

---

## 4. Secure Read-Only Access (`dashboard_ro`)

The AI development layer (running on the VM AI, `100.64.0.14`) needs read
access to `socdb` to power the Flask dashboard and Active Learning loops, but
must **never** be able to alter the traceability records.

### 4.1 Network-level restriction (UFW)
On the VM SOC, PostgreSQL is exposed in Docker, but the host firewall restricts
access strictly to the VM AI:

```bash
sudo ufw allow from 100.64.0.14 to any port 5432 proto tcp
```

### 4.2 Database-level restriction (GRANT)
Inside `socdb`, a dedicated read-only user is created:

```sql
CREATE USER dashboard_ro WITH PASSWORD '<REDACTED>';

GRANT CONNECT ON DATABASE socdb TO dashboard_ro;
GRANT USAGE ON SCHEMA public TO dashboard_ro;

GRANT SELECT ON TABLE alerts TO dashboard_ro;
GRANT SELECT ON TABLE pending_actions TO dashboard_ro;
-- (Also granted on Active Learning tables: analyst_corrections, etc.)
```

This defense-in-depth approach ensures that even if the dashboard application
is compromised, the attacker cannot delete or modify the audit trail.

---

## 5. Validation

```bash
# Connect to the database (from VM SOC)
docker exec -it single-node-postgres-1 psql -U n8n -d socdb

# Check tables and constraints
\d+ alerts
\d+ pending_actions

# Verify read-only user rights
\du dashboard_ro
\dp alerts
\dp pending_actions
```

Expected: `dashboard_ro` only has `r` (read) privileges on the target tables,
and the `uq_alert_action` constraint is visible on `pending_actions`.