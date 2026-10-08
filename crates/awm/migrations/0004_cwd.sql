-- Applied by db::migrate() in one transaction, after the VACUUM INTO backup. Never edit after release.
-- 0004_cwd: the plain working directory behind a cwd_hash, local only (never synced). Rows from
-- before this migration have no cwd row and a NULL injection.cwd_hash until a backfill names them.

CREATE TABLE cwd (
  cwd_hash    TEXT    PRIMARY KEY,   -- sha256 hex of path, as event.cwd_hash
  path        TEXT    NOT NULL,      -- the cwd as the hook / transcript gave it
  repo_root   TEXT,                  -- the main checkout holding path, NULL outside git
  updated_at  INTEGER NOT NULL
);
ALTER TABLE injection ADD COLUMN cwd_hash TEXT;   -- caller cwd at injection time; NULL on old rows
CREATE INDEX injection_cwd ON injection(cwd_hash);
