ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS locked_by     TEXT,
    ADD COLUMN IF NOT EXISTS locked_until  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS attempts      INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_attempts  INT NOT NULL DEFAULT 3;

-- acelera a busca de jobs elegíveis (queued, ou running com lease vencido)
CREATE INDEX IF NOT EXISTS idx_scans_queue
    ON scans (started_at)
    WHERE status IN ('queued', 'running');
