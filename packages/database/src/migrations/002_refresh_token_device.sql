ALTER TABLE refresh_tokens
  ADD COLUMN device_id TEXT REFERENCES devices(id);

CREATE INDEX idx_devices_user_active
  ON devices (user_id, is_revoked);

CREATE INDEX idx_refresh_tokens_user_device_active
  ON refresh_tokens (user_id, device_id, revoked_at, expires_at);
