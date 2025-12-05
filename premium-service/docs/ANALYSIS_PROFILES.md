# Analysis Profiles

VEXxy Premium Analysis supports **predefined analysis profiles** to simplify configuration and optimize scan duration vs. coverage trade-offs.

## Overview

Analysis profiles provide preset configurations for different security assessment scenarios:

| Profile | Use Case | Duration | Features |
|---------|----------|----------|----------|
| **Minimal** | Quick validation, CI/CD gates | ~2-3 min | Passive checks only |
| **Standard** | Balanced security assessment | ~5-10 min | Passive + active fuzzing, profiling |
| **Comprehensive** | Thorough security audit | ~15-20 min | All features, pentesting enabled |
| **Custom** | Advanced users | Variable | User-defined configuration |

## Profile Details

### Minimal Profile

**Best for:** Quick security checks in CI/CD pipelines, pre-production validation

**Configuration:**
```json
{
  "test_timeout": 120,
  "enable_fuzzing": false,
  "enable_profiling": false,
  "enable_pentesting": false,
  "enable_code_coverage": false,
  "health_check_timeout": 30
}
```

**What it does:**
- Verifies application starts and responds
- Runs passive security checks:
  - HTTP vs HTTPS detection
  - Security header analysis (CSP, HSTS, X-Frame-Options, etc.)
  - Server information disclosure
- No active scanning or fuzzing
- Minimal resource usage

**When to use:**
- Fast feedback in development workflows
- Branch protection checks
- Container registry admission webhooks
- Pre-deployment smoke tests

---

### Standard Profile (Default)

**Best for:** Regular security assessments, vulnerability validation

**Configuration:**
```json
{
  "test_timeout": 300,
  "enable_fuzzing": true,
  "enable_profiling": true,
  "enable_pentesting": false,
  "enable_code_coverage": false,
  "health_check_timeout": 60
}
```

**What it does:**
- Full passive security checks
- OWASP ZAP active scanning:
  - Spider crawls application endpoints
  - Fuzzes parameters for common vulnerabilities
  - Tests for OWASP Top 10 issues
- eBPF runtime profiling:
  - Tracks file access patterns
  - Monitors syscalls and network connections
  - Maps loaded libraries
- Reachability analysis for CVEs

**When to use:**
- Scheduled vulnerability assessments
- Release candidate validation
- Default choice for most use cases
- Production container analysis

---

### Comprehensive Profile

**Best for:** Security audits, compliance assessments, high-risk applications

**Configuration:**
```json
{
  "test_timeout": 900,
  "enable_fuzzing": true,
  "enable_profiling": true,
  "enable_pentesting": true,
  "enable_code_coverage": true,
  "health_check_timeout": 120
}
```

**What it does:**
- Everything in Standard profile, plus:
- Aggressive penetration testing
- Code coverage analysis (requires debug symbols)
- Extended fuzzing duration
- Deeper endpoint discovery
- Longer runtime observation

**When to use:**
- Pre-production security audits
- Compliance certifications (SOC 2, ISO 27001)
- High-value/high-risk applications
- Quarterly/annual security reviews
- Before major releases

---

### Custom Profile

**Best for:** Advanced users with specific requirements

**Configuration:** User-provided via `config` field

**What it does:**
- Uses default AnalysisConfig values
- User explicitly sets each parameter
- No preset overrides

**When to use:**
- Fine-tuning specific features
- Experimental configurations
- Performance optimization
- Special compliance requirements

---

## API Usage

### Using Profiles

**Submit analysis with profile:**

```bash
curl -X POST http://localhost:8002/api/v1/analysis/submit \
  -H "Content-Type: application/json" \
  -d '{
    "image_ref": "nginx:latest",
    "image_digest": "sha256:...",
    "profile": "standard"
  }'
```

**Available profile values:**
- `"minimal"`
- `"standard"` (default if omitted)
- `"comprehensive"`
- `"custom"`

### Overriding Profile Settings

Profiles can be customized by providing both `profile` and `config`:

```bash
curl -X POST http://localhost:8002/api/v1/analysis/submit \
  -H "Content-Type: application/json" \
  -d '{
    "image_ref": "nginx:latest",
    "image_digest": "sha256:...",
    "profile": "standard",
    "config": {
      "enable_pentesting": true,
      "ports": [80, 443],
      "environment": {
        "API_KEY": "test-key"
      }
    }
  }'
```

**Merge behavior:**
- Profile provides base configuration
- `config` field overrides specific values
- Allows customization without specifying all parameters

### Custom Profile Example

For full control, use `custom` profile:

```bash
curl -X POST http://localhost:8002/api/v1/analysis/submit \
  -H "Content-Type: application/json" \
  -d '{
    "image_ref": "myapp:v1.2.3",
    "image_digest": "sha256:...",
    "profile": "custom",
    "config": {
      "test_timeout": 600,
      "enable_fuzzing": true,
      "enable_profiling": true,
      "enable_pentesting": false,
      "ports": [8080],
      "command": ["./myapp", "--mode=test"],
      "environment": {
        "LOG_LEVEL": "debug"
      },
      "health_check_path": "/health",
      "health_check_timeout": 90
    }
  }'
```

---

## Profile Selection Guide

### Choose **Minimal** if:
- ✅ You need results in < 5 minutes
- ✅ You're running in CI/CD pipelines
- ✅ You want passive checks only
- ✅ Resource constraints are a concern
- ❌ You need comprehensive vulnerability testing

### Choose **Standard** if:
- ✅ You want balanced coverage and speed
- ✅ You're validating production images
- ✅ You need reachability analysis
- ✅ This is your first analysis of an image
- ❌ You have more than 15 minutes to wait

### Choose **Comprehensive** if:
- ✅ You're conducting security audits
- ✅ Compliance requires thorough testing
- ✅ The application is high-risk
- ✅ You have 15-20+ minutes available
- ❌ You need fast feedback

### Choose **Custom** if:
- ✅ You have specific requirements
- ✅ Default profiles don't fit your needs
- ✅ You're experimenting with settings
- ✅ You need fine-grained control
- ❌ You're a beginner user

---

## Response Format

The job submission response includes the selected profile:

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "image_ref": "nginx:latest",
  "image_digest": "sha256:...",
  "profile": "standard",
  "estimated_duration_minutes": 10,
  "created_at": "2025-12-02T20:00:00Z"
}
```

---

## Best Practices

1. **Use Standard by default** - Good balance for most scenarios
2. **Use Minimal in CI/CD** - Fast feedback loops
3. **Use Comprehensive quarterly** - Thorough audits periodically
4. **Override selectively** - Customize specific settings on Standard profile
5. **Document Custom configs** - If using custom, document your settings
6. **Monitor scan quality** - Check scan coverage metrics in results
7. **Start permissive** - Use Comprehensive first, then optimize to Standard/Minimal

---

## Troubleshooting

### Low Scan Coverage Warning

If you see "Low scan coverage" warnings:

1. **Check if app started correctly:**
   ```bash
   # View evidence logs
   curl http://localhost:8002/api/v1/analysis/{job_id}/results
   # Check container_logs evidence
   ```

2. **Verify ports are exposed:**
   ```json
   {
     "profile": "standard",
     "config": {
       "ports": [8080]  // Add your application port
     }
   }
   ```

3. **Check health endpoint:**
   ```json
   {
     "config": {
       "health_check_path": "/api/health"  // Use your health endpoint
     }
   }
   ```

4. **Provide startup command:**
   ```json
   {
     "config": {
       "command": ["python", "app.py"]
     }
   }
   ```

### Scan Taking Too Long

If scans exceed estimated duration:

1. **Use a faster profile:**
   - Switch from Comprehensive → Standard
   - Switch from Standard → Minimal

2. **Reduce timeout:**
   ```json
   {
     "profile": "standard",
     "config": {
       "test_timeout": 180  // Reduce from default 300s
     }
   }
   ```

3. **Disable heavy features:**
   ```json
   {
     "profile": "standard",
     "config": {
       "enable_profiling": false  // Disable eBPF profiling
     }
   }
   ```

---

## Migration Guide

### From Legacy Configuration

**Before (manual config):**
```json
{
  "image_ref": "nginx:latest",
  "image_digest": "sha256:...",
  "config": {
    "test_timeout": 300,
    "enable_fuzzing": true,
    "enable_profiling": true
  }
}
```

**After (with profile):**
```json
{
  "image_ref": "nginx:latest",
  "image_digest": "sha256:...",
  "profile": "standard"
}
```

Much simpler!

### Backwards Compatibility

- Old API requests without `profile` field still work
- Default profile is **standard**
- Existing `config`-only requests use default profile preset
- No breaking changes

---

## Related Documentation

- [API Reference](../README.md) - Full API documentation
- [OWASP ZAP Setup](./OWASP_ZAP_SETUP.md) - Security scanner configuration
- [Kubescape Architecture](../KUBESCAPE_ARCHITECTURE.md) - Runtime sandbox details
