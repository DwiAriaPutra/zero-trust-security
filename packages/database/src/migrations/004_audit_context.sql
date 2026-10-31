ALTER TABLE audit_logs ADD COLUMN endpoint TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_logs ADD COLUMN device_id TEXT;

UPDATE audit_logs SET endpoint = resource WHERE endpoint = '';
