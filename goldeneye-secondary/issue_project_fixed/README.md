# XML Document Parser - XXE Vulnerability Demo

## Overview

This is a minimal, runnable project demonstrating an **XXE (XML External Entity) vulnerability** in a document parsing system. The project simulates an enterprise document management system that processes invoice XML files.

**⚠️ WARNING: This code contains a deliberate security vulnerability for educational purposes only.**

## Project Structure

```
issue_project/
├── src/
│   ├── __init__.py
│   └── document_parser.py      # Core parser with XXE vulnerability
├── tests/
│   ├── __init__.py
│   └── test_xml_parser.py      # Tests demonstrating the vulnerability
├── data/
│   ├── normal_invoice.xml      # Legitimate invoice file
│   ├── another_normal_invoice.xml
│   ├── xxe_attack_file_read.xml # Malicious XXE payload
│   └── sensitive/
│       └── secret_config.txt   # Simulated sensitive configuration
├── requirements.txt
├── run_tests.bat               # Windows test runner script
├── README.md                   # This file
└── KNOWN_ISSUE.md              # Detailed vulnerability analysis
```

## The Vulnerability

**Type:** CWE-611: Improper Restriction of XML External Entity Reference (XXE)

**Location:** `src/document_parser.py` - `DocumentParser.parse_invoice()` method

**Issue:** The XML parser uses Python's `xml.etree.ElementTree` with default settings, which allows external entity references. An attacker can upload a malicious XML file that reads arbitrary files from the server.

## Quick Start

### Prerequisites
- Python 3.8 or higher
- Windows 11 (tested), or any OS with Python

### Installation

```batch
# Install dependencies (pytest only)
pip install -r requirements.txt
```

### Run Tests

**Option 1: Using the provided script (Windows)**
```batch
run_tests.bat
```

**Option 2: Manual execution**
```batch
# Run all tests with verbose output
pytest tests/ -v

# Run with detailed failure information
pytest tests/ -v --tb=long

# Run specific test
pytest tests/test_xml_parser.py::TestXXEVulnerability::test_xxe_file_read_should_be_blocked -v
```

### Expected Results

- **Basic functionality tests:** ✅ PASS (3 tests)
- **XXE security tests:** ❌ FAIL (4 tests)

The failing tests demonstrate that the parser is vulnerable to XXE attacks.

## Demonstration

### Normal Usage (Safe)
```python
from src.document_parser import DocumentParser

parser = DocumentParser()
result = parser.parse_invoice('data/normal_invoice.xml')
print(result)
# Output: {'id': 'INV-2026-001', 'customer': 'Acme Corporation', 'amount': '5000.00', ...}
```

### XXE Attack (Vulnerable)
```python
parser = DocumentParser()
result = parser.parse_invoice('data/xxe_attack_file_read.xml')
print(result['customer'])
# Output: Contents of secret_config.txt including API keys and passwords! 🚨
```

The malicious XML file (`xxe_attack_file_read.xml`) contains:
```xml
<!DOCTYPE invoice [
  <!ENTITY xxe SYSTEM "file:///C:/BugBash/issue_project/data/sensitive/secret_config.txt">
]>
<invoice>
    <customer>&xxe;</customer>
    ...
</invoice>
```

When parsed, the `&xxe;` entity is replaced with the contents of the sensitive file.

## Issue Details

See [KNOWN_ISSUE.md](KNOWN_ISSUE.md) for:
- Detailed vulnerability analysis
- Attack scenarios
- Impact assessment
- Fix recommendations

## Test Coverage

### Security Tests (Currently Failing ❌)
1. `test_xxe_file_read_should_be_blocked` - Verifies external entities don't leak file contents
2. `test_xxe_external_entity_should_not_be_resolved` - Ensures entity resolution is disabled
3. `test_multiple_entity_references_should_fail` - Checks for sensitive data patterns
4. `test_convenience_function_also_vulnerable` - Validates all entry points

### Functional Tests (Passing ✅)
1. `test_normal_invoice_parsing` - Normal XML processing works correctly
2. `test_normal_invoice_has_required_fields` - Data extraction is accurate
3. `test_missing_file_raises_error` - Error handling works

## Educational Purpose

This project demonstrates:
- How XXE vulnerabilities occur in real-world applications
- Why input validation and secure XML parsing are critical
- How to write security-focused tests
- The difference between functional correctness and security

## License

Educational purposes only. Do not deploy this code in production environments.
