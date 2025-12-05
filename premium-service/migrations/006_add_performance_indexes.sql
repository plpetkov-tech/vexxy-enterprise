-- Migration: Add performance indexes for scalability
-- Date: 2025-12-05
-- Description: Add composite indexes for common query patterns to improve performance at scale
--              These indexes are critical for handling thousands of jobs with multiple concurrent users

-- ============================================================================
-- PREMIUM_ANALYSIS_JOBS TABLE INDEXES
-- ============================================================================

-- Composite index for job listing queries (most common query pattern)
-- Covers: List jobs by organization, filter by status, order by created_at
-- Usage: Dashboard job list, filtered views, status monitoring
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_jobs_org_status_created
ON premium_analysis_jobs(organization_id, status, created_at DESC);

-- Partial index for active jobs monitoring (reduces index size)
-- Covers: Monitor currently active jobs (running, queued, analyzing)
-- Usage: Real-time job monitoring, queue depth tracking
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_jobs_active
ON premium_analysis_jobs(organization_id, created_at DESC)
WHERE status IN ('RUNNING', 'QUEUED', 'ANALYZING');

-- Index for image-based queries
-- Covers: Find all jobs for a specific image digest
-- Usage: Image analysis history, duplicate detection
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_jobs_image_digest_created
ON premium_analysis_jobs(image_digest, created_at DESC);

-- Index for priority-based job queue
-- Covers: Get next job to process ordered by priority and created_at
-- Usage: Worker job selection, priority queue processing
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_jobs_status_priority_created
ON premium_analysis_jobs(status, priority DESC, created_at ASC)
WHERE status IN ('QUEUED', 'RUNNING');

-- Index for completed jobs queries
-- Covers: Find completed/failed jobs within date range
-- Usage: Reporting, analytics, cleanup operations
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_jobs_completed_at
ON premium_analysis_jobs(completed_at DESC)
WHERE completed_at IS NOT NULL;

-- ============================================================================
-- ANALYSIS_EVIDENCE TABLE INDEXES
-- ============================================================================

-- Composite index for evidence queries by job and type
-- Covers: Get evidence for a job, optionally filtered by type
-- Usage: Evidence retrieval, VEX document queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_evidence_job_type_created
ON analysis_evidence(analysis_job_id, evidence_type, created_at DESC);

-- Partial index for VEX documents (JSONB storage)
-- Covers: Find jobs with VEX documents stored in JSONB
-- Usage: VEX document retrieval without file system access
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_evidence_vex_jsonb
ON analysis_evidence(analysis_job_id, created_at DESC)
WHERE vex_document_data IS NOT NULL;

-- ============================================================================
-- NOTES
-- ============================================================================
--
-- CONCURRENTLY: Allows creating indexes without locking the table
-- IF NOT EXISTS: Makes migration idempotent (safe to run multiple times)
--
-- Index Usage Monitoring:
-- To check if indexes are being used, run:
--   SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
--   FROM pg_stat_user_indexes
--   WHERE tablename IN ('premium_analysis_jobs', 'analysis_evidence')
--   ORDER BY idx_scan DESC;
--
-- To find unused indexes (idx_scan = 0):
--   SELECT schemaname, tablename, indexname, pg_size_pretty(pg_relation_size(indexrelid)) as size
--   FROM pg_stat_user_indexes
--   WHERE idx_scan = 0 AND schemaname = 'public'
--   ORDER BY pg_relation_size(indexrelid) DESC;
--
-- Index Size Monitoring:
--   SELECT indexname, pg_size_pretty(pg_relation_size(indexrelid))
--   FROM pg_stat_user_indexes
--   WHERE tablename = 'premium_analysis_jobs'
--   ORDER BY pg_relation_size(indexrelid) DESC;
