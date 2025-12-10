# GitHub Actions Workflows

This directory contains GitHub Actions workflows for the VEXxy Enterprise repository.

## Workflows

### 1. Premium Service Tests (`premium-service-tests.yml`)

**Purpose:** Run comprehensive tests for the premium service with beautiful reporting.

**Triggers:**
- Push to `main`, `develop`, or `claude/**` branches
- Pull requests to `main` or `develop`
- Manual trigger via `workflow_dispatch`
- Only runs when `premium-service/**` files change

**Jobs:**

#### Unit Tests
- Runs all unit tests with pytest
- Generates coverage reports (XML, HTML, terminal)
- Creates beautiful GitHub Actions summaries with:
  - ✅ Test results table (passed/failed/errors/skipped)
  - 📊 Coverage percentages per module
  - 📁 Test file inventory
- Uploads artifacts:
  - Coverage reports (XML + HTML)
  - Test results (JUnit XML)
- Publishes test results as GitHub checks

#### Code Quality
- Runs Ruff linter with GitHub annotations
- Runs Black formatter check
- Runs MyPy type checking (continue-on-error)
- Generates quality summaries

#### Summary
- Aggregates all job results
- Displays final status in GitHub Actions summary

**Example Summary Output:**
```
🎯 VEXxy Premium Service - Test Results

Job Status
| Job | Status |
|-----|--------|
| Unit Tests | ✅ Passed |
| Code Quality | ✅ Passed |

✨ All checks passed! 🎉
```

### 2. VEXxy Enterprise CI (`ci.yml`)

**Purpose:** General CI for the entire vexxy-enterprise repository.

**Triggers:**
- Push to `main`, `develop`, or `claude/**` branches
- Pull requests to `main` or `develop`
- Manual trigger

**Services:**
- PostgreSQL 16 (for integration tests)
- Redis 7 (for Celery tests)

**Jobs:**

#### Tests & Code Quality
- Sets up Python 3.12
- Installs dependencies
- Runs linting (Ruff, Black, MyPy)
- Runs existing integration tests (test_api.py, test_profiles.py)
- Runs new unit tests (tests/unit/)
- Validates Kubernetes manifests
- Uploads coverage reports

## Viewing Test Results

### In GitHub Actions UI

1. Go to the **Actions** tab in GitHub
2. Click on a workflow run
3. View the **Summary** tab for beautiful formatted results

### In Pull Requests

- Test results appear as checks in the PR
- Coverage reports are uploaded as artifacts
- Annotations show linting issues inline in code

## Local Testing

Run the same tests locally before pushing:

```bash
cd premium-service

# Unit tests (fast)
pytest tests/unit/ -v

# With coverage
pytest tests/unit/ --cov=services --cov=workers --cov-report=html

# Code quality
ruff check .
black --check .
mypy .
```

## Adding New Tests

1. Add test files to `premium-service/tests/unit/`
2. Follow naming convention: `test_*.py`
3. Use pytest markers: `@pytest.mark.unit`, `@pytest.mark.kubescape`, etc.
4. Tests will automatically run in CI on next push

## Customizing Reports

The workflows use GitHub Actions job summaries with Markdown formatting:

- **Emojis:** ✅❌⚠️📊🧪🔍 for visual appeal
- **Tables:** For structured data
- **Code blocks:** For command output
- **Badges:** Coverage percentages with color coding

## Artifacts

All test runs preserve artifacts for 30 days:

- **coverage-reports-unit:** Coverage XML + HTML
- **test-results-unit:** JUnit XML test results

Download from the workflow run summary page.

## Troubleshooting

### Tests fail in CI but pass locally

- Check Python version (CI uses 3.12)
- Check environment variables in workflow
- Review the test output in GitHub Actions logs

### Coverage not uploading

- Ensure `coverage.xml` is generated
- Check artifact upload step succeeded
- Verify file paths in workflow

### Workflow not triggering

- Check the `paths` filter in workflow triggers
- Ensure changes are in `premium-service/**`
- Try manual trigger via workflow_dispatch

## Future Enhancements

- **Phase 2:** Integration tests with Kind cluster in CI
- **Phase 3:** E2E smoke tests on nightly schedule
- **Coverage badges:** Auto-generate and commit badges
- **Slack/Discord notifications:** Alert on test failures
- **Performance benchmarks:** Track test execution time
