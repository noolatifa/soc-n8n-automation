-- ===========================================================
-- SOC Blue Team — Read-Only User for AI Dashboard
-- ===========================================================
-- This script creates a restricted user for the AI layer (VM AI, 100.64.0.14)
-- to read traceability data without being able to modify it.
-- It must be combined with host-level UFW rules on the VM SOC:
--   sudo ufw allow from 100.64.0.14 to any port 5432 proto tcp

-- 1. Create the read-only user
CREATE USER dashboard_ro WITH PASSWORD '<REDACTED>';

-- 2. Grant connection and schema usage
GRANT CONNECT ON DATABASE socdb TO dashboard_ro;
GRANT USAGE ON SCHEMA public TO dashboard_ro;

-- 3. Grant read-only access to Blue Team tables
GRANT SELECT ON TABLE alerts TO dashboard_ro;
GRANT SELECT ON TABLE pending_actions TO dashboard_ro;

-- Note: The AI team may additionally grant SELECT on their Active Learning 
-- tables (analyst_corrections, training_dataset, model_versions).