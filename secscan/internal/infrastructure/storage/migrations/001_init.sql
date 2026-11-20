CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    host        TEXT        NOT NULL,
    status      TEXT        NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    data        JSONB       NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);
CREATE INDEX IF NOT EXISTS idx_scans_findings ON scans USING GIN ((data -> 'findings'));
