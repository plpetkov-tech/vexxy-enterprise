-- Migration: Add security_findings column to premium_analysis_jobs
-- Date: 2025-11-15
-- Description: Adds security_findings JSON column to store OWASP ZAP scan results and other security scan data

-- Add the column
ALTER TABLE premium_analysis_jobs
ADD COLUMN IF NOT EXISTS security_findings JSON NULL;

-- Add a comment to document the column
COMMENT ON COLUMN premium_analysis_jobs.security_findings IS 'OWASP ZAP and other security scan results in JSON format';
