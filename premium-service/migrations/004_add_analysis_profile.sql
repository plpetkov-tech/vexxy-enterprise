-- Migration: Add profile column to premium_analysis_jobs
-- Date: 2025-12-02
-- Description: Adds profile column to store analysis profile preset (minimal/standard/comprehensive/custom)

-- Create the enum type for analysis profile
DO $$ BEGIN
    CREATE TYPE analysis_profile AS ENUM ('minimal', 'standard', 'comprehensive', 'custom');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Add the column with default value
ALTER TABLE premium_analysis_jobs
ADD COLUMN IF NOT EXISTS profile analysis_profile DEFAULT 'standard';

-- Add a comment to document the column
COMMENT ON COLUMN premium_analysis_jobs.profile IS 'Analysis profile preset: minimal (passive checks only), standard (balanced), comprehensive (full assessment), custom (user-defined)';
