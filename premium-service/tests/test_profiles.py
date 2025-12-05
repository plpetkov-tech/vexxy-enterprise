"""
Unit tests for analysis profiles feature
"""

import pytest
from api.schemas import (
    AnalysisProfileEnum,
    AnalysisRequest,
    AnalysisConfig,
    get_profile_preset,
)


class TestProfilePresets:
    """Test profile preset configurations"""

    def test_minimal_profile_preset(self):
        """Minimal profile should have passive checks only"""
        preset = get_profile_preset(AnalysisProfileEnum.MINIMAL)

        assert preset["test_timeout"] == 120
        assert preset["enable_fuzzing"] is False
        assert preset["enable_profiling"] is False
        assert preset["enable_pentesting"] is False
        assert preset["enable_code_coverage"] is False
        assert preset["health_check_timeout"] == 30

    def test_standard_profile_preset(self):
        """Standard profile should have balanced settings"""
        preset = get_profile_preset(AnalysisProfileEnum.STANDARD)

        assert preset["test_timeout"] == 300
        assert preset["enable_fuzzing"] is True
        assert preset["enable_profiling"] is True
        assert preset["enable_pentesting"] is False
        assert preset["enable_code_coverage"] is False
        assert preset["health_check_timeout"] == 60

    def test_comprehensive_profile_preset(self):
        """Comprehensive profile should have all features enabled"""
        preset = get_profile_preset(AnalysisProfileEnum.COMPREHENSIVE)

        assert preset["test_timeout"] == 900
        assert preset["enable_fuzzing"] is True
        assert preset["enable_profiling"] is True
        assert preset["enable_pentesting"] is True
        assert preset["enable_code_coverage"] is True
        assert preset["health_check_timeout"] == 120

    def test_custom_profile_preset(self):
        """Custom profile should return empty dict"""
        preset = get_profile_preset(AnalysisProfileEnum.CUSTOM)
        assert preset == {}


class TestAnalysisRequestProfiles:
    """Test AnalysisRequest with profiles"""

    def test_request_with_minimal_profile(self):
        """Request with minimal profile should apply preset"""
        request = AnalysisRequest(
            image_ref="nginx:latest",
            image_digest="sha256:abc123" + "0" * 58,
            profile=AnalysisProfileEnum.MINIMAL,
        )

        assert request.profile == AnalysisProfileEnum.MINIMAL
        assert request.config.test_timeout == 120
        assert request.config.enable_fuzzing is False
        assert request.config.enable_profiling is False

    def test_request_with_standard_profile_default(self):
        """Request without profile should default to standard"""
        request = AnalysisRequest(
            image_ref="nginx:latest", image_digest="sha256:abc123" + "0" * 58
        )

        assert request.profile == AnalysisProfileEnum.STANDARD
        assert request.config.test_timeout == 300
        assert request.config.enable_fuzzing is True
        assert request.config.enable_profiling is True

    def test_request_with_comprehensive_profile(self):
        """Request with comprehensive profile should enable all features"""
        request = AnalysisRequest(
            image_ref="myapp:v1.0",
            image_digest="sha256:def456" + "0" * 58,
            profile=AnalysisProfileEnum.COMPREHENSIVE,
        )

        assert request.profile == AnalysisProfileEnum.COMPREHENSIVE
        assert request.config.test_timeout == 900
        assert request.config.enable_pentesting is True
        assert request.config.enable_code_coverage is True

    def test_profile_with_config_override(self):
        """Config should override profile preset values"""
        request = AnalysisRequest(
            image_ref="nginx:latest",
            image_digest="sha256:abc123" + "0" * 58,
            profile=AnalysisProfileEnum.MINIMAL,
            config=AnalysisConfig(
                enable_fuzzing=True, ports=[80, 443]  # Override minimal preset
            ),
        )

        # Profile preset
        assert request.config.test_timeout == 120  # From minimal preset
        assert request.config.enable_profiling is False  # From minimal preset

        # Custom overrides
        assert request.config.enable_fuzzing is True  # Overridden
        assert request.config.ports == [80, 443]  # Custom value

    def test_custom_profile_with_full_config(self):
        """Custom profile should use only provided config"""
        request = AnalysisRequest(
            image_ref="nginx:latest",
            image_digest="sha256:abc123" + "0" * 58,
            profile=AnalysisProfileEnum.CUSTOM,
            config=AnalysisConfig(
                test_timeout=600,
                enable_fuzzing=True,
                enable_profiling=False,
                ports=[8080],
            ),
        )

        assert request.config.test_timeout == 600
        assert request.config.enable_fuzzing is True
        assert request.config.enable_profiling is False
        assert request.config.ports == [8080]

    def test_invalid_digest_validation(self):
        """Request with invalid digest should raise validation error"""
        with pytest.raises(ValueError, match="pattern"):
            AnalysisRequest(
                image_ref="nginx:latest",
                image_digest="invalid-digest",  # Invalid format
                profile=AnalysisProfileEnum.MINIMAL,
            )

    def test_port_validation(self):
        """Config with invalid ports should raise validation error"""
        with pytest.raises(ValueError, match="Invalid port"):
            AnalysisRequest(
                image_ref="nginx:latest",
                image_digest="sha256:abc123" + "0" * 58,
                config=AnalysisConfig(ports=[80, 99999]),  # Invalid port number
            )

    def test_timeout_validation_min(self):
        """Config with too small timeout should raise validation error"""
        with pytest.raises(ValueError):
            AnalysisRequest(
                image_ref="nginx:latest",
                image_digest="sha256:abc123" + "0" * 58,
                config=AnalysisConfig(test_timeout=30),  # Below minimum of 60
            )

    def test_timeout_validation_max(self):
        """Config with too large timeout should raise validation error"""
        with pytest.raises(ValueError):
            AnalysisRequest(
                image_ref="nginx:latest",
                image_digest="sha256:abc123" + "0" * 58,
                config=AnalysisConfig(test_timeout=1000),  # Above maximum of 900
            )


class TestProfileMerging:
    """Test profile and config merging logic"""

    def test_partial_config_override(self):
        """Partial config should merge with profile preset"""
        request = AnalysisRequest(
            image_ref="nginx:latest",
            image_digest="sha256:abc123" + "0" * 58,
            profile=AnalysisProfileEnum.STANDARD,
            config=AnalysisConfig(ports=[80], environment={"LOG_LEVEL": "debug"}),
        )

        # From standard preset
        assert request.config.test_timeout == 300
        assert request.config.enable_fuzzing is True

        # From custom config
        assert request.config.ports == [80]
        assert request.config.environment == {"LOG_LEVEL": "debug"}

    def test_empty_config_uses_preset(self):
        """Empty config should use full profile preset"""
        request = AnalysisRequest(
            image_ref="nginx:latest",
            image_digest="sha256:abc123" + "0" * 58,
            profile=AnalysisProfileEnum.COMPREHENSIVE,
            config=AnalysisConfig(),
        )

        # All from comprehensive preset
        assert request.config.test_timeout == 900
        assert request.config.enable_fuzzing is True
        assert request.config.enable_profiling is True
        assert request.config.enable_pentesting is True
        assert request.config.enable_code_coverage is True

    def test_none_config_uses_preset(self):
        """None config should apply profile preset"""
        request = AnalysisRequest(
            image_ref="nginx:latest",
            image_digest="sha256:abc123" + "0" * 58,
            profile=AnalysisProfileEnum.MINIMAL,
        )

        # All from minimal preset
        assert request.config.test_timeout == 120
        assert request.config.enable_fuzzing is False
        assert request.config.enable_profiling is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
