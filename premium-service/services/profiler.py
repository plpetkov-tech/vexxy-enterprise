"""
Runtime Profiler Service

Integrates with Tracee for eBPF-based runtime profiling and execution analysis.
"""
from typing import Dict, List, Set, Optional
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class ExecutionProfile:
    """
    Execution profile captured during runtime analysis

    Represents what code was actually executed, what files were accessed,
    what syscalls were made, etc.
    """

    def __init__(self):
        self.duration_seconds: int = 0
        self.files_accessed: Set[str] = set()
        self.files_written: Set[str] = set()
        self.syscalls: Set[str] = set()
        self.syscall_counts: Dict[str, int] = {}
        self.network_connections: Set[str] = set()
        self.processes_spawned: List[str] = []
        self.loaded_libraries: Set[str] = set()
        self.executed_binaries: Set[str] = set()
        self.file_operations: List[Dict] = []

    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        return {
            "duration_seconds": self.duration_seconds,
            "files_accessed": list(self.files_accessed),
            "files_written": list(self.files_written),
            "syscalls": list(self.syscalls),
            "syscall_counts": self.syscall_counts,
            "network_connections": list(self.network_connections),
            "processes_spawned": self.processes_spawned,
            "loaded_libraries": list(self.loaded_libraries),
            "executed_binaries": list(self.executed_binaries),
            "file_operations_count": len(self.file_operations),
            "summary": {
                "total_files_accessed": len(self.files_accessed),
                "total_syscalls": sum(self.syscall_counts.values()),
                "unique_syscalls": len(self.syscalls),
                "network_activity": len(self.network_connections) > 0,
                "child_processes": len(self.processes_spawned),
            }
        }


class TraceeParser:
    """
    Parse Tracee JSON output into execution profiles

    Tracee outputs events in JSON format. We parse these to understand
    what the container actually did during execution.
    """

    # Syscalls that indicate file access
    FILE_SYSCALLS = {
        'open', 'openat', 'openat2', 'creat',
        'read', 'readv', 'pread64', 'preadv', 'preadv2',
        'write', 'writev', 'pwrite64', 'pwritev', 'pwritev2',
        'stat', 'fstat', 'lstat', 'statx',
        'access', 'faccessat', 'faccessat2'
    }

    # Syscalls that indicate network activity
    NETWORK_SYSCALLS = {
        'socket', 'connect', 'accept', 'accept4',
        'bind', 'listen', 'send', 'recv',
        'sendto', 'recvfrom', 'sendmsg', 'recvmsg'
    }

    # Syscalls that indicate process spawning
    PROCESS_SYSCALLS = {
        'fork', 'vfork', 'clone', 'clone3',
        'execve', 'execveat'
    }

    def parse_tracee_output(self, tracee_json: str) -> ExecutionProfile:
        """
        Parse Tracee JSON output

        Args:
            tracee_json: JSON output from Tracee

        Returns:
            ExecutionProfile with parsed data
        """
        profile = ExecutionProfile()

        try:
            # Parse JSON lines (Tracee outputs one JSON object per line)
            events = []
            for line in tracee_json.strip().split('\n'):
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse Tracee line: {line[:100]}")

            if not events:
                logger.warning("No Tracee events found")
                return profile

            logger.info(f"Parsed {len(events)} Tracee events")

            # Calculate duration
            if events:
                timestamps = [e.get('timestamp', 0) for e in events if 'timestamp' in e]
                if timestamps:
                    profile.duration_seconds = int((max(timestamps) - min(timestamps)) / 1000000000)  # ns to s

            # Process each event
            for event in events:
                self._process_event(event, profile)

        except Exception as e:
            logger.error(f"Error parsing Tracee output: {e}", exc_info=True)

        return profile

    def _process_event(self, event: Dict, profile: ExecutionProfile):
        """Process a single Tracee event"""
        event_name = event.get('eventName', '')

        # Track syscall
        if event_name:
            profile.syscalls.add(event_name)
            profile.syscall_counts[event_name] = profile.syscall_counts.get(event_name, 0) + 1

        # Extract arguments
        args = event.get('args', [])

        # File access events
        if event_name in self.FILE_SYSCALLS:
            file_paths = self._extract_file_paths(args)
            for path in file_paths:
                profile.files_accessed.add(path)

                # Track file operations
                profile.file_operations.append({
                    'syscall': event_name,
                    'path': path,
                    'timestamp': event.get('timestamp'),
                })

                # Separate written files
                if 'write' in event_name or event_name == 'creat':
                    profile.files_written.add(path)

                # Track loaded libraries
                if path.endswith(('.so', '.so.0', '.so.1', '.so.2')) or '.so.' in path:
                    profile.loaded_libraries.add(path)

        # Network events
        elif event_name in self.NETWORK_SYSCALLS:
            connection = self._extract_network_info(event, args)
            if connection:
                profile.network_connections.add(connection)

        # Process spawning
        elif event_name in self.PROCESS_SYSCALLS:
            process = self._extract_process_info(event, args)
            if process:
                profile.processes_spawned.append(process)

                # Track executed binaries
                if event_name in ['execve', 'execveat']:
                    binary = self._extract_binary_path(args)
                    if binary:
                        profile.executed_binaries.add(binary)

    def _extract_file_paths(self, args: List[Dict]) -> List[str]:
        """Extract file paths from syscall arguments"""
        paths = []
        for arg in args:
            arg_name = arg.get('name', '')
            if arg_name in ['pathname', 'filename', 'path', 'name', 'dirfd']:
                value = arg.get('value')
                if value and isinstance(value, str) and value.startswith('/'):
                    paths.append(value)
        return paths

    def _extract_network_info(self, event: Dict, args: List[Dict]) -> Optional[str]:
        """Extract network connection info"""
        for arg in args:
            if arg.get('name') == 'addr':
                addr = arg.get('value', {})
                if isinstance(addr, dict):
                    ip = addr.get('sin_addr', addr.get('sin6_addr'))
                    port = addr.get('sin_port')
                    if ip and port:
                        return f"{ip}:{port}"
        return None

    def _extract_process_info(self, event: Dict, args: List[Dict]) -> Optional[str]:
        """Extract spawned process info"""
        for arg in args:
            if arg.get('name') in ['filename', 'pathname']:
                return arg.get('value')
        return None

    def _extract_binary_path(self, args: List[Dict]) -> Optional[str]:
        """Extract binary path from exec syscall"""
        for arg in args:
            if arg.get('name') in ['filename', 'pathname']:
                path = arg.get('value')
                if path and isinstance(path, str):
                    return path
        return None


class ProfilerService:
    """
    Service for managing runtime profiling with Tracee
    """

    def __init__(self):
        self.parser = TraceeParser()

    def parse_tracee_logs(self, tracee_output: str) -> ExecutionProfile:
        """
        Parse Tracee output into execution profile

        Args:
            tracee_output: Raw Tracee JSON output

        Returns:
            ExecutionProfile
        """
        logger.info("Parsing Tracee output")
        profile = self.parser.parse_tracee_output(tracee_output)

        logger.info(f"Profile summary: {profile.to_dict()['summary']}")
        return profile

    def analyze_code_coverage(self, profile: ExecutionProfile, sbom_components: List[Dict]) -> float:
        """
        Estimate code coverage based on executed files

        This is a rough estimate - actual code coverage requires instrumentation.
        We estimate by comparing executed files to total files in the image.

        Args:
            profile: Execution profile
            sbom_components: SBOM components (files in the image)

        Returns:
            Estimated coverage percentage (0-100)
        """
        if not sbom_components:
            return 0.0

        # Get all files from SBOM
        total_files = set()
        for component in sbom_components:
            # Extract file paths from component
            if 'purl' in component and 'file' in component['purl']:
                total_files.add(component['purl'])

        if not total_files:
            # Fallback: use a typical distribution (rough estimate)
            total_files = {f"/usr/lib/{i}" for i in range(1000)}

        # Calculate coverage
        executed_files = profile.files_accessed
        if not total_files:
            return 0.0

        coverage = len(executed_files) / len(total_files) * 100
        return min(coverage, 100.0)  # Cap at 100%
