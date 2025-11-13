"""
SBOM Integration Service

Integrates with VEXxy core backend to fetch SBOMs and vulnerability data.
"""
from typing import Dict, List, Optional
import logging
import httpx
from uuid import UUID

from config.settings import settings

logger = logging.getLogger(__name__)


class SBOMService:
    """
    Service for fetching and processing SBOMs

    Integrates with VEXxy core backend API.
    """

    def __init__(self):
        self.base_url = settings.vexxy_backend_url
        self.api_key = settings.vexxy_api_key
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
            timeout=30.0
        )

    async def fetch_sbom(self, sbom_id: UUID) -> Optional[Dict]:
        """
        Fetch SBOM from VEXxy backend

        Args:
            sbom_id: SBOM UUID

        Returns:
            SBOM document or None if not found
        """
        try:
            response = await self.client.get(f"/api/v1/sboms/{sbom_id}")
            response.raise_for_status()

            sbom = response.json()
            logger.info(f"Fetched SBOM {sbom_id}: {len(sbom.get('components', []))} components")
            return sbom

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"SBOM {sbom_id} not found")
                return None
            logger.error(f"Failed to fetch SBOM: {e}")
            raise
        except Exception as e:
            logger.error(f"Error fetching SBOM: {e}", exc_info=True)
            raise

    async def fetch_vulnerabilities(self, sbom_id: UUID) -> List[Dict]:
        """
        Fetch vulnerabilities for SBOM

        Args:
            sbom_id: SBOM UUID

        Returns:
            List of vulnerabilities
        """
        try:
            response = await self.client.get(f"/api/v1/sboms/{sbom_id}/vulnerabilities")
            response.raise_for_status()

            vulnerabilities = response.json()
            logger.info(f"Fetched {len(vulnerabilities)} vulnerabilities for SBOM {sbom_id}")
            return vulnerabilities

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"No vulnerabilities found for SBOM {sbom_id}")
                return []
            logger.error(f"Failed to fetch vulnerabilities: {e}")
            raise
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities: {e}", exc_info=True)
            raise

    async def fetch_sbom_by_image(self, image_ref: str, image_digest: str) -> Optional[Dict]:
        """
        Fetch SBOM by image reference

        Args:
            image_ref: Container image reference
            image_digest: Image digest

        Returns:
            SBOM document or None
        """
        try:
            response = await self.client.get(
                "/api/v1/sboms/search",
                params={
                    "image_ref": image_ref,
                    "image_digest": image_digest
                }
            )
            response.raise_for_status()

            results = response.json()
            if results:
                sbom = results[0]  # Take first match
                logger.info(f"Found SBOM for {image_ref}@{image_digest}")
                return sbom
            else:
                logger.warning(f"No SBOM found for {image_ref}@{image_digest}")
                return None

        except Exception as e:
            logger.error(f"Error fetching SBOM by image: {e}", exc_info=True)
            return None

    def parse_sbom_components(self, sbom: Dict) -> List[Dict]:
        """
        Parse components from SBOM

        Handles both CycloneDX and SPDX formats.

        Args:
            sbom: SBOM document

        Returns:
            List of components
        """
        components = []

        # CycloneDX format
        if 'bomFormat' in sbom and sbom['bomFormat'] == 'CycloneDX':
            components = sbom.get('components', [])

        # SPDX format
        elif 'spdxVersion' in sbom:
            packages = sbom.get('packages', [])
            for pkg in packages:
                components.append({
                    'name': pkg.get('name'),
                    'version': pkg.get('versionInfo'),
                    'purl': pkg.get('externalRefs', [{}])[0].get('referenceLocator'),
                    'type': pkg.get('packageType', 'library')
                })

        logger.debug(f"Parsed {len(components)} components from SBOM")
        return components

    def extract_vulnerabilities_from_sbom(self, sbom: Dict) -> List[Dict]:
        """
        Extract vulnerabilities from SBOM (if embedded)

        Args:
            sbom: SBOM document

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        # CycloneDX with vulnerabilities
        if 'vulnerabilities' in sbom:
            vulnerabilities = sbom['vulnerabilities']

        # Components with vulnerabilities
        components = sbom.get('components', [])
        for component in components:
            comp_vulns = component.get('vulnerabilities', [])
            for vuln in comp_vulns:
                vuln['affects'] = [component]  # Add component reference
                vulnerabilities.append(vuln)

        logger.debug(f"Extracted {len(vulnerabilities)} vulnerabilities from SBOM")
        return vulnerabilities

    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()


class MockSBOMService(SBOMService):
    """
    Mock SBOM service for testing

    Returns mock data when VEXxy backend is not available.
    """

    async def fetch_sbom(self, sbom_id: UUID) -> Optional[Dict]:
        """Return mock SBOM"""
        logger.info(f"Using mock SBOM for {sbom_id}")
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "openssl",
                    "version": "1.1.1",
                    "purl": "pkg:deb/debian/openssl@1.1.1",
                },
                {
                    "type": "library",
                    "name": "libcurl",
                    "version": "7.68.0",
                    "purl": "pkg:deb/debian/libcurl@7.68.0",
                }
            ]
        }

    async def fetch_vulnerabilities(self, sbom_id: UUID) -> List[Dict]:
        """Return mock vulnerabilities"""
        logger.info(f"Using mock vulnerabilities for {sbom_id}")
        return [
            {
                "id": "CVE-2024-12345",
                "source": {
                    "name": "NVD"
                },
                "ratings": [
                    {
                        "score": 7.5,
                        "severity": "high"
                    }
                ],
                "affects": [
                    {
                        "ref": "pkg:deb/debian/openssl@1.1.1"
                    }
                ]
            },
            {
                "id": "CVE-2024-67890",
                "source": {
                    "name": "NVD"
                },
                "ratings": [
                    {
                        "score": 5.0,
                        "severity": "medium"
                    }
                ],
                "affects": [
                    {
                        "ref": "pkg:deb/debian/libcurl@7.68.0"
                    }
                ]
            }
        ]

    async def fetch_sbom_by_image(self, image_ref: str, image_digest: str) -> Optional[Dict]:
        """Return mock SBOM for any image"""
        logger.info(f"Using mock SBOM for {image_ref}")
        return await self.fetch_sbom(UUID('00000000-0000-0000-0000-000000000000'))
