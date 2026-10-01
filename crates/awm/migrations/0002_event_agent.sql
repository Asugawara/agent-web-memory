-- Applied by db::migrate() in one transaction, after 0001_init. Never edit after release.
-- event.agent: which coding agent made the call. Rows from before this migration are 'claude'.
-- event.source stays 'hook' / 'import' (record::Record::db_source maps the Codex sources).

ALTER TABLE event ADD COLUMN agent TEXT NOT NULL DEFAULT 'claude' CHECK (agent IN ('claude','codex'));
