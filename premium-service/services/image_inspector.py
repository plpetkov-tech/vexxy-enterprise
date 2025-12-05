"""
Image Inspector Service

Inspects container images to extract metadata and detect application frameworks.
Used for auto-detecting startup commands for security scanning.
"""

import logging
import json
import subprocess
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ImageInspector:
    """
    Service for inspecting container images to extract configuration metadata

    Capabilities:
    - Extract ENTRYPOINT, CMD, ENV, WORKDIR from image manifest
    - Detect application framework (FastAPI, Node, Go, Java, etc.)
    - Generate appropriate startup commands
    """

    def __init__(self):
        self.cache = {}  # Cache inspection results

    def inspect_image(self, image_ref: str) -> Optional[Dict]:
        """
        Inspect image to extract configuration metadata

        Args:
            image_ref: Container image reference (e.g., ghcr.io/user/image:tag)

        Returns:
            Dict with image config (Cmd, Entrypoint, Env, WorkingDir, ExposedPorts, Labels)
            or None if inspection fails
        """
        # Check cache
        if image_ref in self.cache:
            logger.debug(f"Using cached inspection for {image_ref}")
            return self.cache[image_ref]

        logger.info(f"Inspecting image: {image_ref}")

        try:
            # Try using crictl (containerd CLI) - works in K8s clusters
            result = self._inspect_with_crictl(image_ref)
            if result:
                self.cache[image_ref] = result
                return result

            # Fallback to docker CLI if available
            result = self._inspect_with_docker(image_ref)
            if result:
                self.cache[image_ref] = result
                return result

            # Fallback to skopeo (doesn't require daemon)
            result = self._inspect_with_skopeo(image_ref)
            if result:
                self.cache[image_ref] = result
                return result

            logger.warning(
                f"Could not inspect image {image_ref} with any available tool"
            )
            return None

        except Exception as e:
            logger.error(f"Error inspecting image {image_ref}: {e}", exc_info=True)
            return None

    def _inspect_with_crictl(self, image_ref: str) -> Optional[Dict]:
        """Inspect using crictl (containerd CLI)"""
        try:
            # First, check if image is present
            result = subprocess.run(
                ["crictl", "inspecti", image_ref],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                logger.debug(f"crictl inspect failed: {result.stderr}")
                return None

            data = json.loads(result.stdout)

            # Extract config from crictl output
            if "status" in data and "config" in data["status"]:
                config = data["status"]["config"]
                return {
                    "Cmd": config.get("command"),
                    "Entrypoint": config.get("entrypoint"),
                    "Env": config.get("env", []),
                    "WorkingDir": config.get("workingDir"),
                    "ExposedPorts": config.get("exposedPorts", {}),
                    "Labels": config.get("labels", {}),
                }

            return None

        except (
            subprocess.TimeoutExpired,
            FileNotFoundError,
            json.JSONDecodeError,
        ) as e:
            logger.debug(f"crictl not available or failed: {e}")
            return None

    def _inspect_with_docker(self, image_ref: str) -> Optional[Dict]:
        """Inspect using docker CLI"""
        try:
            result = subprocess.run(
                ["docker", "inspect", image_ref],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                logger.debug(f"docker inspect failed: {result.stderr}")
                return None

            data = json.loads(result.stdout)
            if not data:
                return None

            # Extract config from docker output
            config = data[0].get("Config", {})
            return {
                "Cmd": config.get("Cmd"),
                "Entrypoint": config.get("Entrypoint"),
                "Env": config.get("Env", []),
                "WorkingDir": config.get("WorkingDir"),
                "ExposedPorts": config.get("ExposedPorts", {}),
                "Labels": config.get("Labels", {}),
            }

        except (
            subprocess.TimeoutExpired,
            FileNotFoundError,
            json.JSONDecodeError,
        ) as e:
            logger.debug(f"docker not available or failed: {e}")
            return None

    def _inspect_with_skopeo(self, image_ref: str) -> Optional[Dict]:
        """Inspect using skopeo (no daemon required)"""
        try:
            # Normalize image ref for skopeo
            if not image_ref.startswith("docker://"):
                skopeo_ref = f"docker://{image_ref}"
            else:
                skopeo_ref = image_ref

            result = subprocess.run(
                ["skopeo", "inspect", skopeo_ref],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode != 0:
                logger.debug(f"skopeo inspect failed: {result.stderr}")
                return None

            data = json.loads(result.stdout)

            # Extract config from skopeo output
            return {
                "Cmd": data.get("Cmd"),
                "Entrypoint": data.get("Entrypoint"),
                "Env": data.get("Env", []),
                "WorkingDir": data.get("WorkingDir"),
                "ExposedPorts": data.get("ExposedPorts", {}),
                "Labels": data.get("Labels", {}),
            }

        except (
            subprocess.TimeoutExpired,
            FileNotFoundError,
            json.JSONDecodeError,
        ) as e:
            logger.debug(f"skopeo not available or failed: {e}")
            return None

    def construct_command_from_config(self, image_config: Dict) -> Optional[List[str]]:
        """
        Construct full command from ENTRYPOINT and CMD

        Docker/OCI spec:
        - If both ENTRYPOINT and CMD are present: command = ENTRYPOINT + CMD
        - If only ENTRYPOINT: command = ENTRYPOINT
        - If only CMD: command = CMD

        Args:
            image_config: Dict from inspect_image()

        Returns:
            Command as list of strings, or None if no command defined
        """
        entrypoint = image_config.get("Entrypoint") or []
        cmd = image_config.get("Cmd") or []

        # Normalize to lists
        if isinstance(entrypoint, str):
            entrypoint = [entrypoint]
        if isinstance(cmd, str):
            cmd = [cmd]

        # Combine according to Docker/OCI spec
        if entrypoint and cmd:
            command = entrypoint + cmd
        elif entrypoint:
            command = entrypoint
        elif cmd:
            command = cmd
        else:
            return None

        # Filter out empty strings
        command = [c for c in command if c]

        if not command:
            return None

        logger.info(f"Constructed command from image config: {command}")
        return command

    def detect_framework(self, image_config: Dict) -> Optional[str]:
        """
        Detect application framework from image metadata

        Args:
            image_config: Dict from inspect_image()

        Returns:
            Framework name (fastapi, flask, django, express, springboot, go, etc.) or None
        """
        env_vars = image_config.get("Env", [])
        labels = image_config.get("Labels", {})
        working_dir = image_config.get("WorkingDir", "")

        # Convert env list to dict for easier checking
        env_dict = {}
        for env_str in env_vars:
            if "=" in env_str:
                key, value = env_str.split("=", 1)
                env_dict[key] = value

        # Check labels for framework hints
        for label, value in labels.items():
            label_lower = label.lower()
            if "fastapi" in label_lower or "uvicorn" in label_lower:
                return "fastapi"
            if "flask" in label_lower:
                return "flask"
            if "django" in label_lower:
                return "django"
            if "express" in label_lower or "node" in label_lower:
                return "express"
            if "springboot" in label_lower or "spring-boot" in label_lower:
                return "springboot"

        # Check environment variables
        if "FASTAPI_ENV" in env_dict or "UVICORN_PORT" in env_dict:
            return "fastapi"
        if "FLASK_APP" in env_dict:
            return "flask"
        if "DJANGO_SETTINGS_MODULE" in env_dict:
            return "django"
        if "NODE_ENV" in env_dict or "NPM_CONFIG_PRODUCTION" in env_dict:
            return "express"
        if "JAVA_HOME" in env_dict and "spring" in working_dir.lower():
            return "springboot"

        # Check for Python-based frameworks (fallback)
        python_indicators = ["PYTHONPATH", "PYTHON_VERSION", "PIP_VERSION"]
        if any(ind in env_dict for ind in python_indicators):
            # Could be FastAPI, Flask, or Django - default to FastAPI (most common for APIs)
            logger.debug("Detected Python environment, assuming FastAPI")
            return "fastapi"

        # Check for Node.js
        node_indicators = ["NODE_VERSION", "NPM_VERSION", "YARN_VERSION"]
        if any(ind in env_dict for ind in node_indicators):
            logger.debug("Detected Node.js environment, assuming Express")
            return "express"

        # Check for Go
        if "GOLANG_VERSION" in env_dict or "GOPATH" in env_dict:
            return "go"

        # Check for Java
        if "JAVA_VERSION" in env_dict or "JAVA_HOME" in env_dict:
            return "springboot"

        logger.debug("Could not detect framework from image metadata")
        return None

    def get_framework_startup_command(
        self, framework: str, ports: List[int], working_dir: str = "/app"
    ) -> Optional[List[str]]:
        """
        Get typical startup command for detected framework

        Args:
            framework: Framework name from detect_framework()
            ports: List of exposed ports
            working_dir: Working directory

        Returns:
            Startup command as list of strings, or None if unknown framework
        """
        port = ports[0] if ports else 8000  # Default to first port or 8000

        framework_commands = {
            "fastapi": [
                "uvicorn",
                "main:app",
                "--host",
                "0.0.0.0",
                "--port",
                str(port),
            ],
            "flask": ["flask", "run", "--host", "0.0.0.0", "--port", str(port)],
            "django": ["python", "manage.py", "runserver", f"0.0.0.0:{port}"],
            "express": ["node", "server.js"],  # or npm start
            "springboot": ["java", "-jar", "app.jar"],
            "go": ["./app"],  # Assume binary is named 'app'
        }

        command = framework_commands.get(framework)

        if command:
            logger.info(f"Generated {framework} startup command: {command}")
        else:
            logger.warning(f"No startup command template for framework: {framework}")

        return command

    def determine_startup_command(
        self,
        image_ref: str,
        user_command: Optional[List[str]] = None,
        ports: Optional[List[int]] = None,
        require_command_for_ports: bool = True,
    ) -> Tuple[Optional[List[str]], str]:
        """
        Determine startup command using hybrid approach

        Priority:
        1. User-specified command (highest priority)
        2. Image CMD/ENTRYPOINT from manifest
        3. Framework detection + generated command
        4. None (will use sleep as fallback, or fail if ports specified)

        Args:
            image_ref: Container image reference
            user_command: User-specified command (overrides all)
            ports: List of ports to expose
            require_command_for_ports: If True, fail when ports specified but no command found

        Returns:
            Tuple of (command, source) where source is one of:
            - "user_specified"
            - "image_metadata"
            - "framework_detection"
            - "none"
        """
        # 1. User override (highest priority)
        if user_command:
            logger.info(f"Using user-specified command: {user_command}")
            return user_command, "user_specified"

        # 2. Image metadata (CMD/ENTRYPOINT)
        image_config = self.inspect_image(image_ref)
        if image_config:
            command = self.construct_command_from_config(image_config)
            if command:
                logger.info(f"Using command from image metadata: {command}")
                return command, "image_metadata"

            # 3. Framework detection (fallback)
            framework = self.detect_framework(image_config)
            if framework:
                working_dir = image_config.get("WorkingDir", "/app")
                command = self.get_framework_startup_command(
                    framework, ports or [], working_dir
                )
                if command:
                    logger.warning(
                        f"Image has no CMD/ENTRYPOINT. Using detected {framework} command: {command}"
                    )
                    return command, "framework_detection"

        # 4. No command found
        if require_command_for_ports and ports:
            logger.error(
                f"Cannot determine startup command for {image_ref} but ports {ports} were specified. "
                f"Security scanning requires a running application. "
                f"Please specify 'command' in your analysis config."
            )
            return None, "none"

        logger.warning(
            f"No command detected for {image_ref}. "
            f"Will use sleep (profiling-only mode)."
        )
        return None, "none"


# Singleton instance
_inspector = None


def get_image_inspector() -> ImageInspector:
    """Get singleton ImageInspector instance"""
    global _inspector
    if _inspector is None:
        _inspector = ImageInspector()
    return _inspector
