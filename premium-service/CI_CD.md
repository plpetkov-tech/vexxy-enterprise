# CI/CD and Testing Guide

This guide explains how to use the automated testing and CI/CD pipelines for the VEXxy Premium Service.

## 🚀 Quick Start

### Running Tests Locally

```bash
cd /home/plamen/all-vexxy/vexxy-enterprise/premium-service

# Install dependencies
pip install -r requirements-dev.txt

# Run all unit tests
pytest tests/unit/ -v

# Run with coverage
pytest tests/unit/ --cov=services --cov=workers --cov-report=html

# Open coverage report
xdg-open htmlcov/index.html
```

### Viewing Test Results in GitHub

1. **Go to GitHub Actions:**
   - Navigate to: `https://github.com/YOUR_ORG/vexxy-enterprise/actions`

2. **Find your workflow run:**
   - Click on "Premium Service Tests" workflow
   - Select your recent commit/PR

3. **View beautiful summaries:**
   - Click the **Summary** tab
   - See test results, coverage, and file listings

## 📊 What Gets Tested in CI

### Automated on Every Push/PR

When you push code or create a PR, GitHub Actions automatically:

1. **Unit Tests** (`tests/unit/`)
   - ✅ 78+ tests covering KubescapeService, VEX processing, ZAPService
   - 📊 Coverage tracking (services/, workers/, api/)
   - ⚡ Runs in ~1-2 minutes

2. **Code Quality**
   - 🔍 Ruff linting
   - 🎨 Black formatting
   - 🔎 MyPy type checking

3. **Integration Tests** (existing)
   - 🧪 API endpoint tests
   - 🧪 Profile tests
   - 🗄️ Database integration (PostgreSQL)
   - 📮 Redis integration

## 📈 Understanding the Test Summary

### Example GitHub Actions Summary

```markdown
## 🧪 Unit Test Results

| Metric | Count |
|--------|-------|
| ✅ Passed | 75 |
| ❌ Failed | 0 |
| ⚠️ Errors | 0 |
| ⏭️ Skipped | 3 |
| 📊 Total | 78 |

### ✨ All tests passed! 🎉

## 📊 Code Coverage

**Overall Coverage:** `73.2%`

🟡 Coverage: 73.2%

### Coverage by Module

| Module | Coverage |
|--------|----------|
| `services.kubescape` | 🟢 85.4% |
| `services.owasp_zap` | 🟢 82.1% |
| `workers.tasks_impl_kubescape` | 🟡 68.3% |
| `api.main` | 🟡 65.7% |

## 📁 Test Files

| File | Tests | Lines |
|------|-------|-------|
| `test_kubescape_service.py` | 25 | 653 |
| `test_vex_processing.py` | 30 | 507 |
| `test_zap_service.py` | 23 | 556 |
```

### Coverage Badge Colors

- 🟢 **Green (≥80%):** Excellent coverage
- 🟡 **Yellow (60-79%):** Good coverage, room for improvement
- 🔴 **Red (<60%):** Needs more tests

## 🔧 Workflow Files

### `premium-service-tests.yml`

Dedicated workflow for premium service tests with beautiful reporting.

**Features:**
- ✨ Emoji-rich summaries
- 📊 Coverage percentages per module
- 📋 Test file inventory
- 🎯 Artifact uploads (coverage reports, test results)
- ✅ GitHub Check annotations

### `ci.yml`

General CI workflow for the entire repository.

**Features:**
- 🐘 PostgreSQL + Redis services
- 🧪 Integration tests
- 🔍 Code quality checks
- 📦 Kubernetes manifest validation

## 📦 Artifacts

After each test run, artifacts are saved for 30 days:

### Coverage Reports
- **Location:** Workflow run → Artifacts → `coverage-reports-unit`
- **Contents:**
  - `coverage.xml` - For external tools
  - `htmlcov/` - Interactive HTML report

### Test Results
- **Location:** Workflow run → Artifacts → `test-results-unit`
- **Contents:**
  - `test-results.xml` - JUnit XML format

### Downloading Artifacts

1. Go to workflow run summary
2. Scroll to **Artifacts** section
3. Click artifact name to download ZIP

## 🎯 Test Markers

Tests are organized with markers for selective running:

```python
@pytest.mark.unit          # Fast unit tests (run in CI)
@pytest.mark.integration   # Integration tests (TODO: Phase 2)
@pytest.mark.kubescape     # Kubescape-specific tests
@pytest.mark.zap           # ZAP-specific tests
@pytest.mark.pentest       # Pentesting tests
@pytest.mark.slow          # Tests taking >5 seconds
```

### Running Specific Test Categories

```bash
# Only Kubescape tests
pytest tests/unit/ -v -m kubescape

# Only ZAP tests
pytest tests/unit/ -v -m zap

# All except slow tests
pytest tests/ -v -m "not slow"
```

## 🚨 Handling Test Failures in CI

### Step 1: View the Failure

1. Go to GitHub Actions
2. Click the failed workflow run
3. Click the failed job
4. Expand the failed step

### Step 2: Understand the Error

Look for:
- ❌ **AssertionError:** Expected vs actual values
- 🐛 **Exception:** Runtime errors
- ⚠️ **Import errors:** Missing dependencies

### Step 3: Reproduce Locally

```bash
# Run the exact failing test
pytest tests/unit/test_kubescape_service.py::test_extract_runtime_vex_success -vv

# Run with more detail
pytest tests/unit/ -vv --tb=long
```

### Step 4: Fix and Verify

```bash
# Fix the code
# ...

# Run tests again
pytest tests/unit/ -v

# Push the fix
git add .
git commit -m "fix: resolve test failure in kubescape service"
git push
```

## 📝 Adding New Tests

### 1. Create Test File

```bash
cd premium-service/tests/unit
touch test_my_new_feature.py
```

### 2. Write Tests

```python
import pytest
from services.my_service import MyService

@pytest.mark.unit
def test_my_new_feature():
    service = MyService()
    result = service.do_something()
    assert result == expected_value
```

### 3. Run Locally

```bash
pytest tests/unit/test_my_new_feature.py -v
```

### 4. Push and Verify

```bash
git add tests/unit/test_my_new_feature.py
git commit -m "test: add tests for my new feature"
git push
```

CI will automatically run your new tests!

## 🎨 Customizing CI Behavior

### Skip CI for Documentation Changes

Add `[skip ci]` to commit message:

```bash
git commit -m "docs: update README [skip ci]"
```

### Run Workflow Manually

1. Go to GitHub Actions
2. Select "Premium Service Tests"
3. Click "Run workflow"
4. Choose branch and click "Run workflow"

### Override Test Markers

Edit `.github/workflows/premium-service-tests.yml`:

```yaml
# Run different markers
pytest tests/unit/ -v -m "unit and not slow"
```

## 📊 Coverage Goals

### Current Status (Phase 1)
- **Target:** 70%+ on services/
- **Actual:** Will be measured in first CI run

### Future Goals
- **Phase 2:** 80%+ on services/
- **Phase 3:** 85%+ overall with integration tests

## 🔄 Workflow Triggers

### Premium Service Tests Workflow

**Runs when:**
- ✅ Push to `main`, `develop`, `claude/**`
- ✅ PR to `main` or `develop`
- ✅ Files in `premium-service/**` change
- ✅ Manual trigger

**Does NOT run when:**
- ❌ Only documentation changes (README, etc.)
- ❌ Changes outside `premium-service/`
- ❌ Draft PRs (unless explicitly run)

## 🐛 Troubleshooting

### "Module not found" in CI

**Problem:** Test passes locally but fails in CI with import error.

**Solution:**
```bash
# Add to requirements-dev.txt
echo "missing-package==1.0.0" >> requirements-dev.txt
git add requirements-dev.txt
git commit -m "deps: add missing test dependency"
```

### Coverage is lower in CI than locally

**Problem:** Local coverage is 80%, CI shows 60%.

**Solution:**
- Check if all test files are being discovered
- Verify `pytest` paths in workflow
- Ensure all source directories are included in `--cov` flags

### Tests timeout in CI

**Problem:** Tests hang or timeout after 10+ minutes.

**Solution:**
```bash
# Add timeout to slow tests
@pytest.mark.slow
@pytest.mark.timeout(60)  # 60 second timeout
def test_slow_operation():
    ...
```

## 📚 Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
- [Test Strategy Plan](/home/plamen/.claude/plans/functional-discovering-hamster.md)
- [Test Documentation](tests/README.md)
- [Workflow Documentation](../.github/workflows/README.md)

## 🎯 Next Steps

1. **Run your first CI build:**
   ```bash
   git add .
   git commit -m "feat: add comprehensive test suite with CI/CD"
   git push
   ```

2. **View the beautiful summary in GitHub Actions**

3. **Download coverage report and review**

4. **Add more tests incrementally as you develop**

5. **Phase 2:** Add integration tests with Kind cluster

---

*Happy Testing! 🧪*
