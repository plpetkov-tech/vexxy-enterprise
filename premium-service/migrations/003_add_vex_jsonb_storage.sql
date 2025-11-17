-- Migration: Add JSONB storage for VEX documents
-- This allows VEX documents to be stored directly in the database
-- instead of as separate files, enabling shared access between API and worker pods

-- Add JSONB column for storing VEX document data
ALTER TABLE analysis_evidence
ADD COLUMN IF NOT EXISTS vex_document_data JSONB;

-- Create GIN index for fast JSONB queries (optional but recommended)
CREATE INDEX IF NOT EXISTS idx_vex_document_data
ON analysis_evidence USING gin (vex_document_data);

-- Make storage_path nullable since we can now store in database
ALTER TABLE analysis_evidence
ALTER COLUMN storage_path DROP NOT NULL;

-- Add constraint to ensure either file storage OR database storage is used
-- (but not both or neither)
ALTER TABLE analysis_evidence
DROP CONSTRAINT IF EXISTS evidence_has_data;

ALTER TABLE analysis_evidence
ADD CONSTRAINT evidence_has_data
CHECK (
  (storage_path IS NOT NULL AND vex_document_data IS NULL) OR
  (storage_path IS NULL AND vex_document_data IS NOT NULL)
);

-- Add comment for documentation
COMMENT ON COLUMN analysis_evidence.vex_document_data IS
'VEX document stored as JSONB. Preferred over storage_path for VEX documents to enable shared access between pods.';
