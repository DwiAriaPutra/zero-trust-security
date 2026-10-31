ALTER TABLE users ADD COLUMN nim TEXT;
CREATE UNIQUE INDEX idx_users_nim_unique ON users(nim) WHERE nim IS NOT NULL;
UPDATE users SET nim = id WHERE role = 'MAHASISWA' AND nim IS NULL;

ALTER TABLE classes
  ADD COLUMN grade_version INTEGER NOT NULL DEFAULT 0 CHECK (grade_version >= 0);
