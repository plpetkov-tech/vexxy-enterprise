"""
Evidence Collection and Storage Service

Manages collection, storage, and retrieval of analysis evidence.
"""

from typing import Dict, Optional, Tuple
from pathlib import Path
import json
import hashlib
import logging
from datetime import datetime
from uuid import UUID, uuid4

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

        if self.backend == "local":
            self.base_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Using local storage: {self.base_path}")

    def store_evidence(
        self,
        job_id: UUID,
        evidence_type: EvidenceType,
        data: str,
        description: Optional[str] = None,
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
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{evidence_type.value}_{timestamp}.json"
        file_path = job_dir / filename

        # Write data
        try:
            with open(file_path, "w") as f:
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
                    description=description,
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
            with open(storage_path, "r") as f:
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
            description="Tracee eBPF profiler JSON output",
        )

    def store_execution_profile(self, job_id: UUID, profile: Dict) -> str:
        """Store parsed execution profile"""
        return self.store_evidence(
            job_id=job_id,
            evidence_type=EvidenceType.EXECUTION_TRACE,
            data=json.dumps(profile, indent=2),
            description="Parsed execution profile",
        )

    def store_reachability_results(self, job_id: UUID, results: Dict) -> str:
        """Store reachability analysis results"""
        return self.store_evidence(
            job_id=job_id,
            evidence_type=EvidenceType.CODE_COVERAGE,
            data=json.dumps(results, indent=2),
            description="CVE reachability analysis results",
        )

    def store_fuzzing_results(self, job_id: UUID, results: Dict) -> str:
        """Store fuzzing results"""
        return self.store_evidence(
            job_id=job_id,
            evidence_type=EvidenceType.FUZZING_RESULTS,
            data=json.dumps(results, indent=2),
            description="OWASP ZAP fuzzing results",
        )

    def store_profiling_data(self, job_id: UUID, profiling_data: Dict) -> str:
        """Store raw profiling data (Tracee events)"""
        return self.store_evidence(
            job_id=job_id,
            evidence_type=EvidenceType.PROFILER_OUTPUT,
            data=json.dumps(profiling_data, indent=2),
            description="Runtime profiling data (Tracee/eBPF)",
        )

    def store_container_logs(
        self, job_id: UUID, logs: str, container_name: str = "target"
    ) -> str:
        """Store container startup logs for diagnostics"""
        return self.store_evidence(
            job_id=job_id,
            evidence_type=EvidenceType.CONTAINER_LOGS,
            data=logs,
            description=f"Container startup logs for {container_name}",
        )

    def store_health_check_results(self, job_id: UUID, health_status: Dict) -> str:
        """Store application health check results"""
        return self.store_evidence(
            job_id=job_id,
            evidence_type=EvidenceType.HEALTH_CHECK,
            data=json.dumps(health_status, indent=2),
            description="Application health verification results",
        )

    def store_zap_scan_logs(self, job_id: UUID, scan_logs: str) -> str:
        """Store detailed ZAP scan logs"""
        return self.store_evidence(
            job_id=job_id,
            evidence_type=EvidenceType.ZAP_SCAN_LOGS,
            data=scan_logs,
            description="OWASP ZAP detailed scan logs",
        )

    def store_vex_document(self, job_id: UUID, vex_document: Dict) -> Tuple[str, UUID]:
        """
        Store VEX document in database and return reference + VEX ID

        Args:
            job_id: Analysis job ID
            vex_document: VEX document to store

        Returns:
            Tuple of (db_reference, vex_id)
        """
        # Generate unique VEX ID
        vex_id = uuid4()

        # Add VEX ID to document metadata if it has vexxy_metadata
        if "vexxy_metadata" in vex_document:
            vex_document["vexxy_metadata"]["vex_id"] = str(vex_id)

        # Store directly in database as JSONB
        db = SessionLocal()
        try:
            evidence = AnalysisEvidence(
                analysis_job_id=job_id,
                evidence_type=EvidenceType.PROFILER_OUTPUT,
                vex_document_data=vex_document,  # Store in JSONB column
                description=f"Kubescape runtime VEX document (ID: {vex_id})",
            )
            db.add(evidence)
            db.commit()
            db.refresh(evidence)

            logger.info(
                f"Stored VEX document with ID {vex_id} in database (evidence ID: {evidence.id})"
            )
            return f"db://vex/{vex_id}", vex_id

        except Exception as e:
            db.rollback()
            logger.error(f"Failed to store VEX document: {e}", exc_info=True)
            raise
        finally:
            db.close()

    def retrieve_vex_by_id(self, vex_id: UUID) -> Optional[Dict]:
        """
        Retrieve VEX document by its ID from database

        Args:
            vex_id: VEX document UUID

        Returns:
            VEX document dict, or None if not found
        """
        db = SessionLocal()
        try:
            # Find evidence record with VEX ID in description and JSONB data
            evidence = (
                db.query(AnalysisEvidence)
                .filter(
                    AnalysisEvidence.description.like(f"%ID: {vex_id}%"),
                    AnalysisEvidence.evidence_type == EvidenceType.PROFILER_OUTPUT,
                    AnalysisEvidence.vex_document_data.isnot(None),
                )
                .first()
            )

            if not evidence:
                logger.warning(f"No VEX document found with ID {vex_id}")
                return None

            # Return JSONB data directly
            return evidence.vex_document_data

        except Exception as e:
            logger.error(
                f"Failed to retrieve VEX document {vex_id}: {e}", exc_info=True
            )
            return None
        finally:
            db.close()

    def store_filtered_sbom(self, job_id: UUID, filtered_sbom: Dict) -> str:
        """Store filtered SBOM from Kubescape"""
        return self.store_evidence(
            job_id=job_id,
            evidence_type=EvidenceType.EXECUTION_TRACE,  # Reuse existing type
            data=json.dumps(filtered_sbom, indent=2),
            description="Kubescape filtered SBOM (relevant components only)",
        )
