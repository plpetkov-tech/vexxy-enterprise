"""
Evidence Collection and Storage Service

Manages collection, storage, and retrieval of analysis evidence.
"""
from typing import Dict, Optional
from pathlib import Path
import json
import hashlib
import logging
from datetime import datetime
from uuid import UUID

from config.settings import settings
from models import SessionLocal, AnalysisEvidence, EvidenceType

logger = logging.getLogger(__name__)


class EvidenceStorage:
    """
    Store and retrieve evidence files

    Supports multiple backends: local filesystem, S3, GCS, MinIO
    """

    def __init__(self):
        self.backend = settings.storage_backend
        self.base_path = Path(settings.storage_path)

        if self.backend == 'local':
            self.base_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Using local storage: {self.base_path}")

    def store_evidence(
        self,
        job_id: UUID,
        evidence_type: EvidenceType,
        data: str,
        description: Optional[str] = None
    ) -> str:
        """
        Store evidence and return storage path

        Args:
            job_id: Analysis job ID
            evidence_type: Type of evidence
            data: Evidence data (JSON string or text)
            description: Optional description

        Returns:
            Storage path
        """
        # Create job directory
        job_dir = self.base_path / str(job_id)
        job_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"{evidence_type.value}_{timestamp}.json"
        file_path = job_dir / filename

        # Write data
        try:
            with open(file_path, 'w') as f:
                f.write(data)

            logger.info(f"Stored evidence: {file_path}")

            # Calculate checksum
            checksum = hashlib.sha256(data.encode()).hexdigest()

            # Save to database
            db = SessionLocal()
            try:
                evidence = AnalysisEvidence(
                    analysis_job_id=job_id,
                    evidence_type=evidence_type,
                    storage_path=str(file_path),
                    file_size=len(data),
                    checksum=checksum,
                    description=description
                )
                db.add(evidence)
                db.commit()
                logger.info(f"Saved evidence record to database: {evidence.id}")

            finally:
                db.close()

            return str(file_path)

        except Exception as e:
            logger.error(f"Failed to store evidence: {e}", exc_info=True)
            raise

    def retrieve_evidence(self, storage_path: str) -> str:
        """
        Retrieve evidence from storage

        Args:
            storage_path: Path to evidence file

        Returns:
            Evidence data
        """
        try:
            with open(storage_path, 'r') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to retrieve evidence from {storage_path}: {e}")
            raise

    def store_tracee_output(self, job_id: UUID, tracee_json: str) -> str:
        """Store Tracee profiler output"""
        return self.store_evidence(
            job_id=job_id,
            evidence_type=EvidenceType.PROFILER_OUTPUT,
            data=tracee_json,
            description="Tracee eBPF profiler JSON output"
        )

    def store_execution_profile(self, job_id: UUID, profile: Dict) -> str:
        """Store parsed execution profile"""
        return self.store_evidence(
            job_id=job_id,
            evidence_type=EvidenceType.EXECUTION_TRACE,
            data=json.dumps(profile, indent=2),
            description="Parsed execution profile"
        )

    def store_reachability_results(self, job_id: UUID, results: Dict) -> str:
        """Store reachability analysis results"""
        return self.store_evidence(
            job_id=job_id,
            evidence_type=EvidenceType.CODE_COVERAGE,
            data=json.dumps(results, indent=2),
            description="CVE reachability analysis results"
        )

    def store_fuzzing_results(self, job_id: UUID, results: Dict) -> str:
        """Store fuzzing results"""
        return self.store_evidence(
            job_id=job_id,
            evidence_type=EvidenceType.FUZZING_RESULTS,
            data=json.dumps(results, indent=2),
            description="OWASP ZAP fuzzing results"
        )
