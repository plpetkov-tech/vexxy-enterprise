-- Migration: Convert profile column from enum to varchar
-- Date: 2025-12-02
-- Description: Simplify profile column to varchar to avoid enum casting issues

-- Convert profile column to varchar
ALTER TABLE premium_analysis_jobs
ALTER COLUMN profile TYPE VARCHAR(20) USING profile::text;

-- Drop the enum type (optional, keeping it doesn't hurt)
-- DROP TYPE IF EXISTS analysis_profile;
