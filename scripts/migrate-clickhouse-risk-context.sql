-- Administrator expand step for #453. Run once before rolling out new ingest
-- workers; harmless when bootstrap/new-install schema already has the column.
-- No old scores are recalculated. Empty strings on old rows mean no receipt.
ALTER TABLE shapoclyack.shapoclyack_vulnerabilities
    ADD COLUMN IF NOT EXISTS risk_assessment String DEFAULT '';
