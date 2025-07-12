# Test Directory Organization

This directory contains all tests for the API Gateway project, properly organized by test type and scope.

## Directory Structure

```
tests/
├── __init__.py                 # Test package initialization
├── .coverage                   # Coverage report data
├── htmlcov/                    # HTML coverage reports
├── logs/                       # Test execution logs
├── fixtures/                   # Test data and fixtures
├── unit/                       # Unit tests
│   └── __init__.py
├── integration/                # Integration tests
│   ├── __init__.py
│   ├── test_api_keys.py        # API key management tests
│   ├── test_config.py          # Configuration tests
│   ├── test_gateway.py         # Gateway functionality tests
│   ├── test_jwt_auth.py        # JWT authentication tests
│   ├── test_service_registry.py # Service registry tests
│   ├── test_weather.py         # Weather service tests
│   └── validate_api_keys.py    # API key validation script
└── test_rbac_integration.py    # RBAC system integration tests
```

## Test Categories

### Unit Tests (`unit/`)
- Test individual components in isolation
- Mock external dependencies
- Fast execution
- High coverage

### Integration Tests (`integration/`)
- Test component interactions
- Use real services where appropriate
- End-to-end scenarios
- API endpoint testing

## Running Tests

### All Tests
```bash
# Run all tests with coverage
pytest tests/ --cov=app --cov-report=html

# Run specific test category
pytest tests/unit/          # Unit tests only
pytest tests/integration/   # Integration tests only
```

### Specific Test Files
```bash
# Test specific functionality
pytest tests/integration/test_api_keys.py
pytest tests/integration/test_jwt_auth.py
pytest tests/test_rbac_integration.py
```

### Using the Test Runner
```bash
# Use the project test runner script
python scripts/run_tests.py
```

## Test Configuration

Tests use the following configuration:
- **pytest** as the test framework
- **coverage** for code coverage reporting
- **async** support for FastAPI testing
- **fixtures** for test data setup
- **mocking** for external dependencies

## Coverage Reports

Coverage reports are generated in multiple formats:
- **Terminal output**: Quick coverage summary
- **HTML reports**: Detailed line-by-line coverage in `htmlcov/`
- **Coverage data**: Raw coverage data in `.coverage`

## Test Data and Fixtures

Test fixtures and data are organized in the `fixtures/` directory:
- **Mock data**: Sample API responses, test users, etc.
- **Configuration**: Test-specific config files
- **Certificates**: Test SSL certificates and keys

## Best Practices

1. **Isolation**: Each test should be independent
2. **Naming**: Use descriptive test names that explain what is being tested
3. **Setup/Teardown**: Use fixtures for test setup and cleanup
4. **Assertions**: Use specific assertions with clear error messages
5. **Documentation**: Document complex test scenarios

## Integration with CI/CD

Tests are designed to run in CI/CD pipelines:
- **Environment-agnostic**: Tests work in any environment
- **Docker-compatible**: Can run in containerized environments
- **Parallel execution**: Tests can run in parallel for speed
- **Failure reporting**: Clear failure messages and logs

## Previous Organization

**Note**: Test files were previously located in `scripts/` but have been moved to this proper test directory structure for better organization and maintainability.
