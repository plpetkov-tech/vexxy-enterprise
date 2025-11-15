"""
Kubernetes Configuration Utility

Provides centralized kubeconfig loading to avoid multiple load attempts.
The Kubernetes Python client expects configuration to be loaded once per process.
"""
from kubernetes import client, config
import logging
import threading

logger = logging.getLogger(__name__)

# Thread-safe flag to track if config has been loaded
_config_loaded = False
_config_lock = threading.Lock()


def load_kubernetes_config(in_cluster: bool = False) -> bool:
    """
    Load Kubernetes configuration (thread-safe, idempotent)

    This function ensures the configuration is only loaded once per process,
    even if called multiple times from different threads.

    Args:
        in_cluster: If True, use in-cluster config; otherwise use kubeconfig file

    Returns:
        True if config loaded successfully (or already loaded), False on error

    Raises:
        Exception: If configuration loading fails critically
    """
    global _config_loaded

    with _config_lock:
        if _config_loaded:
            logger.debug("Kubernetes configuration already loaded, skipping reload")
            return True

        try:
            if in_cluster:
                config.load_incluster_config()
                logger.info("Loaded in-cluster Kubernetes configuration")
            else:
                config.load_kube_config()
                logger.info("Loaded local kubeconfig")

            _config_loaded = True
            return True

        except Exception as e:
            logger.error(f"Failed to load Kubernetes config: {e}", exc_info=True)
            raise


def is_config_loaded() -> bool:
    """Check if Kubernetes configuration has been loaded"""
    return _config_loaded


def get_api_client() -> client.ApiClient:
    """
    Get Kubernetes API client

    Returns:
        ApiClient instance

    Raises:
        RuntimeError: If configuration has not been loaded yet
    """
    if not _config_loaded:
        raise RuntimeError(
            "Kubernetes configuration not loaded. "
            "Call load_kubernetes_config() first."
        )
    return client.ApiClient()


def get_core_v1_api() -> client.CoreV1Api:
    """Get CoreV1Api instance"""
    if not _config_loaded:
        raise RuntimeError(
            "Kubernetes configuration not loaded. "
            "Call load_kubernetes_config() first."
        )
    return client.CoreV1Api()


def get_apps_v1_api() -> client.AppsV1Api:
    """Get AppsV1Api instance"""
    if not _config_loaded:
        raise RuntimeError(
            "Kubernetes configuration not loaded. "
            "Call load_kubernetes_config() first."
        )
    return client.AppsV1Api()


def get_batch_v1_api() -> client.BatchV1Api:
    """Get BatchV1Api instance"""
    if not _config_loaded:
        raise RuntimeError(
            "Kubernetes configuration not loaded. "
            "Call load_kubernetes_config() first."
        )
    return client.BatchV1Api()


def get_custom_objects_api() -> client.CustomObjectsApi:
    """Get CustomObjectsApi instance"""
    if not _config_loaded:
        raise RuntimeError(
            "Kubernetes configuration not loaded. "
            "Call load_kubernetes_config() first."
        )
    return client.CustomObjectsApi()


def get_apiextensions_v1_api() -> client.ApiextensionsV1Api:
    """Get ApiextensionsV1Api instance"""
    if not _config_loaded:
        raise RuntimeError(
            "Kubernetes configuration not loaded. "
            "Call load_kubernetes_config() first."
        )
    return client.ApiextensionsV1Api()
