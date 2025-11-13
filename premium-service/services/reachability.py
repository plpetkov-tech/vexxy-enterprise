"""
Reachability Analyzer

Determines if CVEs are reachable based on runtime execution evidence.
This is the core premium feature - proving vulnerability reachability.
"""
from typing import Dict, List, Set, Optional, Tuple
import logging
from dataclasses import dataclass
from enum import Enum

from .profiler import ExecutionProfile

logger = logging.getLogger(__name__)


class VulnerabilityStatus(str, Enum):
    """VEX vulnerability status values"""
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNDER_INVESTIGATION = "under_investigation"
    FIXED = "fixed"


class VexJustification(str, Enum):
    """OpenVEX justification codes"""
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = "vulnerable_code_cannot_be_controlled_by_adversary"
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


@dataclass
class ReachabilityResult:
    """Result of reachability analysis for a single CVE"""
    cve_id: str
    status: VulnerabilityStatus
    justification: Optional[VexJustification]
    confidence_score: float  # 0.0 - 1.0
    reason: str
    vulnerable_files: List[str]
    executed_files: List[str]
    evidence: Dict

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "cve_id": self.cve_id,
            "status": self.status.value,
            "justification": self.justification.value if self.justification else None,
            "confidence_score": round(self.confidence_score, 2),
            "reason": self.reason,
            "vulnerable_files": self.vulnerable_files,
            "executed_files": self.executed_files,
            "evidence": self.evidence
        }


class CVEMapper:
    """
    Map CVEs to vulnerable code locations

    Uses various heuristics to map a CVE to specific files/functions
    in the container image.
    """

    def __init__(self):
        self.cve_database: Dict[str, Dict] = {}

    def map_cve_to_files(self, cve_id: str, component: Dict) -> List[str]:
        """
        Map CVE to vulnerable file paths

        Args:
            cve_id: CVE identifier
            component: Vulnerable component from SBOM

        Returns:
            List of file paths that contain the vulnerability
        """
        vulnerable_files = []

        # Extract component information
        component_name = component.get('name', '')
        component_version = component.get('version', '')
        purl = component.get('purl', '')

        logger.debug(f"Mapping {cve_id} to files in {component_name}@{component_version}")

        # Strategy 1: Use PURL to identify file locations
        if purl:
            files = self._purl_to_files(purl)
            vulnerable_files.extend(files)

        # Strategy 2: Use component type and name
        comp_type = component.get('type', '')
        if comp_type == 'library':
            files = self._library_to_files(component_name)
            vulnerable_files.extend(files)

        # Strategy 3: Check common locations for packages
        if 'python' in component_name.lower() or comp_type == 'pypi':
            vulnerable_files.extend(self._python_package_files(component_name))
        elif 'npm' in purl or comp_type == 'npm':
            vulnerable_files.extend(self._npm_package_files(component_name))
        elif 'maven' in purl or comp_type == 'maven':
            vulnerable_files.extend(self._java_package_files(component_name))

        # Strategy 4: Use CVE-specific database (if available)
        if cve_id in self.cve_database:
            cve_files = self.cve_database[cve_id].get('files', [])
            vulnerable_files.extend(cve_files)

        # Remove duplicates
        vulnerable_files = list(set(vulnerable_files))

        if not vulnerable_files:
            logger.warning(f"Could not map {cve_id} to specific files")
            # Fallback: guess based on component name
            vulnerable_files = [f"/usr/lib/{component_name}", f"/usr/local/lib/{component_name}"]

        logger.info(f"Mapped {cve_id} to {len(vulnerable_files)} files")
        return vulnerable_files

    def _purl_to_files(self, purl: str) -> List[str]:
        """Convert PURL to file paths"""
        files = []

        # Extract package name from PURL
        # Example: pkg:pypi/flask@2.0.0 -> /usr/local/lib/python3.11/site-packages/flask/
        if 'pkg:' in purl:
            parts = purl.split('/')
            if len(parts) >= 2:
                package = parts[-1].split('@')[0]

                if 'pypi' in purl:
                    files.append(f"/usr/local/lib/python3.*/site-packages/{package}/")
                elif 'npm' in purl:
                    files.append(f"/usr/local/lib/node_modules/{package}/")
                elif 'maven' in purl:
                    files.append(f"/usr/share/java/{package}.jar")

        return files

    def _library_to_files(self, lib_name: str) -> List[str]:
        """Map library name to file paths"""
        return [
            f"/usr/lib/{lib_name}.so",
            f"/usr/lib/x86_64-linux-gnu/{lib_name}.so",
            f"/lib/{lib_name}.so",
            f"/lib/x86_64-linux-gnu/{lib_name}.so",
        ]

    def _python_package_files(self, package_name: str) -> List[str]:
        """Map Python package to typical file locations"""
        return [
            f"/usr/local/lib/python3.11/site-packages/{package_name}/",
            f"/usr/lib/python3/dist-packages/{package_name}/",
            f"/opt/python/lib/python3.11/site-packages/{package_name}/",
        ]

    def _npm_package_files(self, package_name: str) -> List[str]:
        """Map npm package to typical file locations"""
        return [
            f"/usr/local/lib/node_modules/{package_name}/",
            f"/node_modules/{package_name}/",
            f"/app/node_modules/{package_name}/",
        ]

    def _java_package_files(self, package_name: str) -> List[str]:
        """Map Java package to typical file locations"""
        return [
            f"/usr/share/java/{package_name}.jar",
            f"/app/lib/{package_name}.jar",
        ]


class ReachabilityAnalyzer:
    """
    Analyze vulnerability reachability based on runtime execution

    This is the core of the premium feature - determining if a CVE is actually
    exploitable based on what code was executed.
    """

    def __init__(self):
        self.cve_mapper = CVEMapper()

    def analyze_cve_reachability(
        self,
        cve_id: str,
        component: Dict,
        execution_profile: ExecutionProfile,
        sbom: Dict
    ) -> ReachabilityResult:
        """
        Analyze if a CVE is reachable based on execution evidence

        Args:
            cve_id: CVE identifier
            component: Vulnerable component from SBOM
            execution_profile: Runtime execution data
            sbom: Full SBOM for context

        Returns:
            ReachabilityResult with status and confidence score
        """
        logger.info(f"Analyzing reachability for {cve_id}")

        # Step 1: Map CVE to vulnerable files
        vulnerable_files = self.cve_mapper.map_cve_to_files(cve_id, component)

        # Step 2: Check if vulnerable files were executed
        executed_files = list(execution_profile.files_accessed)

        # Step 3: Determine reachability
        reachability = self._determine_reachability(
            vulnerable_files,
            executed_files,
            execution_profile
        )

        # Step 4: Calculate confidence score
        confidence = self._calculate_confidence(
            reachability,
            execution_profile,
            vulnerable_files,
            executed_files
        )

        # Step 5: Generate result
        result = self._create_result(
            cve_id,
            reachability,
            confidence,
            vulnerable_files,
            executed_files,
            execution_profile
        )

        logger.info(
            f"{cve_id}: {result.status.value} "
            f"(confidence: {result.confidence_score:.2f})"
        )

        return result

    def _determine_reachability(
        self,
        vulnerable_files: List[str],
        executed_files: List[str],
        profile: ExecutionProfile
    ) -> Tuple[VulnerabilityStatus, Optional[VexJustification]]:
        """
        Determine if vulnerable code is reachable

        Returns:
            (status, justification)
        """
        # Check for exact file matches
        executed_set = set(executed_files)
        vulnerable_set = set(vulnerable_files)

        # Direct match: file was executed
        if vulnerable_set.intersection(executed_set):
            logger.debug("Direct file match - code was executed")
            return VulnerabilityStatus.AFFECTED, None

        # Partial match: check if any executed file contains vulnerable path
        for vuln_file in vulnerable_files:
            for exec_file in executed_files:
                # Handle wildcards and partial paths
                if self._path_matches(vuln_file, exec_file):
                    logger.debug(f"Partial match: {vuln_file} ~ {exec_file}")
                    return VulnerabilityStatus.AFFECTED, None

        # Check if vulnerable library was loaded
        for vuln_file in vulnerable_files:
            if any(vuln_file in lib for lib in profile.loaded_libraries):
                logger.debug(f"Library loaded but not executed: {vuln_file}")
                # Library loaded but not executed - medium confidence not affected
                return (
                    VulnerabilityStatus.NOT_AFFECTED,
                    VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
                )

        # No match found - code not executed
        logger.debug("No match found - vulnerable code not in execute path")
        return (
            VulnerabilityStatus.NOT_AFFECTED,
            VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
        )

    def _path_matches(self, pattern: str, path: str) -> bool:
        """Check if path matches pattern (supports wildcards)"""
        import re

        # Convert shell-style wildcards to regex
        # /usr/lib/python3.*/site-packages/flask/ -> /usr/lib/python3\..*/site-packages/flask/
        pattern = pattern.replace('.', r'\.').replace('*', '.*')

        try:
            return bool(re.match(pattern, path))
        except re.error:
            return pattern in path

    def _calculate_confidence(
        self,
        reachability: Tuple[VulnerabilityStatus, Optional[VexJustification]],
        profile: ExecutionProfile,
        vulnerable_files: List[str],
        executed_files: List[str]
    ) -> float:
        """
        Calculate confidence score (0.0 - 1.0)

        Factors:
        - Code coverage: higher coverage = higher confidence
        - File match quality: exact match vs partial vs none
        - Test duration: longer test = more code paths explored
        - Number of syscalls: more activity = better coverage
        """
        status, justification = reachability

        # Base confidence
        if status == VulnerabilityStatus.AFFECTED:
            # Found execution - high confidence
            base_confidence = 0.9
        else:
            # Not found - confidence depends on how thoroughly we tested
            base_confidence = 0.7

        # Adjust for code coverage (if available)
        coverage_factor = min(len(executed_files) / 100, 1.0)  # Normalize by typical file count
        confidence = base_confidence + (coverage_factor * 0.1)

        # Adjust for test duration (longer = more thorough)
        if profile.duration_seconds < 60:
            confidence -= 0.1  # Short test, lower confidence
        elif profile.duration_seconds > 300:
            confidence += 0.05  # Long test, higher confidence

        # Adjust for syscall activity
        if profile.syscall_counts:
            total_syscalls = sum(profile.syscall_counts.values())
            if total_syscalls > 1000:
                confidence += 0.05  # High activity, good coverage
            elif total_syscalls < 100:
                confidence -= 0.1  # Low activity, poor coverage

        # Cap between 0.0 and 1.0
        confidence = max(0.0, min(1.0, confidence))

        return confidence

    def _create_result(
        self,
        cve_id: str,
        reachability: Tuple[VulnerabilityStatus, Optional[VexJustification]],
        confidence: float,
        vulnerable_files: List[str],
        executed_files: List[str],
        profile: ExecutionProfile
    ) -> ReachabilityResult:
        """Create reachability result"""
        status, justification = reachability

        # Generate reason text
        if status == VulnerabilityStatus.AFFECTED:
            reason = (
                f"Vulnerable code was executed during runtime analysis. "
                f"Found {len(set(vulnerable_files).intersection(executed_files))} "
                f"matching file(s) in execution trace."
            )
        else:
            reason = (
                f"Vulnerable code exists but was not executed during comprehensive testing. "
                f"Analyzed {len(executed_files)} executed files and "
                f"{sum(profile.syscall_counts.values())} syscalls over "
                f"{profile.duration_seconds} seconds."
            )

        # Build evidence
        evidence = {
            "vulnerable_files": vulnerable_files,
            "executed_files": executed_files[:50],  # Limit for storage
            "execution_summary": profile.to_dict()['summary'],
            "test_duration_seconds": profile.duration_seconds,
            "total_syscalls": sum(profile.syscall_counts.values()),
            "unique_syscalls": len(profile.syscalls),
            "network_activity": len(profile.network_connections) > 0,
            "child_processes": len(profile.processes_spawned),
        }

        return ReachabilityResult(
            cve_id=cve_id,
            status=status,
            justification=justification,
            confidence_score=confidence,
            reason=reason,
            vulnerable_files=vulnerable_files,
            executed_files=executed_files,
            evidence=evidence
        )

    def analyze_all_cves(
        self,
        vulnerabilities: List[Dict],
        execution_profile: ExecutionProfile,
        sbom: Dict
    ) -> List[ReachabilityResult]:
        """
        Analyze reachability for all CVEs in the SBOM

        Args:
            vulnerabilities: List of CVEs from SBOM
            execution_profile: Runtime execution data
            sbom: Full SBOM

        Returns:
            List of ReachabilityResults
        """
        results = []

        logger.info(f"Analyzing {len(vulnerabilities)} CVEs for reachability")

        for vuln in vulnerabilities:
            try:
                cve_id = vuln.get('id', vuln.get('cve_id', 'UNKNOWN'))
                component = vuln.get('affects', [{}])[0] if vuln.get('affects') else {}

                result = self.analyze_cve_reachability(
                    cve_id=cve_id,
                    component=component,
                    execution_profile=execution_profile,
                    sbom=sbom
                )

                results.append(result)

            except Exception as e:
                logger.error(f"Failed to analyze {vuln.get('id')}: {e}", exc_info=True)
                # Continue with other CVEs

        # Summary
        not_affected = sum(1 for r in results if r.status == VulnerabilityStatus.NOT_AFFECTED)
        affected = sum(1 for r in results if r.status == VulnerabilityStatus.AFFECTED)

        logger.info(
            f"Reachability analysis complete: "
            f"{not_affected} not affected, {affected} affected"
        )

        return results
