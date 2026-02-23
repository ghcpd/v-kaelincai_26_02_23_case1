# XML Document Parser - XXE Vulnerability Demo (FIXED)

## Overview

This is a fixed version of the XML document parser that demonstrates an **XXE (XML External Entity) vulnerability** has been successfully remediated. The project simulates an enterprise document management system that processes invoice XML files securely.

**✅ FIXED: This code no longer contains the XXE vulnerability - external entities are blocked.**

## Project Structure

```
issue_project_fixed/
├── src/
│   ├── __init__.py
│   └── document_parser.py      # Core parser with XXE vulnerability FIXED
├── tests/
│   ├── __init__.py
│   └── test_xml_parser.py      # Tests for vulnerability detection
├── data/
│   ├── normal_invoice.xml      # Legitimate invoice file
│   ├── another_normal_invoice.xml
│   ├── xxe_attack_file_read.xml # Malicious XXE payload (now blocked)
│   └── sensitive/
│       └── secret_config.txt   # Simulated sensitive configuration
├── requirements.txt
├── run_tests.bat               # Windows test runner script
├── README.md                   # This file
└── KNOWN_ISSUE.md              # Detailed vulnerability analysis
```

## The Fix

**Type:** CWE-611: Improper Restriction of XML External Entity Reference (XXE) - FIXED

**Location:** `src/document_parser.py` - `DocumentParser.parse_invoice()` method

**Fix Applied:** The XML parser now uses `defusedxml.ElementTree.parse()` instead of the standard library, which automatically disables external entity references. This prevents attackers from uploading malicious XML files that read arbitrary files from the server.

### What Changed

**Before (Vulnerable):**
```python
import xml.etree.ElementTree as ET
tree = ET.parse(xml_file_path)  # External entities are resolved!
```

**After (Secure):**
```python
from defusedxml.ElementTree import parse as safe_parse
tree = safe_parse(xml_file_path)  # External entities are blocked!
```

## Quick Start

### Prerequisites
- Python 3.8 or higher
- Windows 11 (tested), or any OS with Python

### Installation

```batch
# Install dependencies (including security fix)
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

✅ **All 7 tests should now PASS:**
- Basic functionality tests: ✅ PASS (3 tests)
- XXE security tests: ✅ PASS (4 tests)

The malicious XML file is now safely rejected, and sensitive data cannot be leaked.

## Demonstration

### Normal Usage (Safe)
```python
from src.document_parser import DocumentParser

parser = DocumentParser()
result = parser.parse_invoice('data/normal_invoice.xml')
print(result)
# Output: {'id': 'INV-2026-001', 'customer': 'Acme Corporation', 'amount': '5000.00', ...}
```

### XXE Attack (Now Blocked ✅)
```python
parser = DocumentParser()
result = parser.parse_invoice('data/xxe_attack_file_read.xml')
print(result['customer'])
# Output: '&xxe;' or error - sensitive file is NOT exposed! ✅
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

When parsed with the fix, the `&xxe;` entity reference is safely ignored or blocked, and file contents are NOT leaked.

## Issue Details

See [KNOWN_ISSUE.md](KNOWN_ISSUE.md) for:
- Detailed vulnerability analysis
- Original attack scenarios
- Impact assessment
- Fix recommendations

## Test Coverage

### Security Tests (Now Passing ✅)
1. `test_xxe_file_read_should_be_blocked` - ✅ External entities don't leak file contents
2. `test_xxe_external_entity_should_not_be_resolved` - ✅ Entity resolution is disabled
3. `test_multiple_entity_references_should_fail` - ✅ No sensitive data patterns found
4. `test_convenience_function_also_vulnerable` - ✅ All entry points are protected

### Functional Tests (Passing ✅)
1. `test_normal_invoice_parsing` - Normal XML processing works correctly
2. `test_normal_invoice_has_required_fields` - Data extraction is accurate
3. `test_missing_file_raises_error` - Error handling works

## The Security Fix

The fix uses the `defusedxml` library, which:
- ✅ Prevents XXE (External Entity) attacks
- ✅ Protects against XML Bomb attacks
- ✅ Blocks entity expansion
- ✅ Maintains full XML parsing functionality
- ✅ Is a drop-in replacement for ElementTree

### Why defusedxml?

According to Python's XML documentation, the standard library's XML parsers are vulnerable to several types of XML attacks. The `defusedxml` library provides secure implementations:

> "The XML processing modules are not secure against maliciously constructed data. It is possible to construct XML inputs that causes Python XML processing modules to consume large amounts of memory or CPU time."

## Educational Purpose

This project demonstrates:
- How XXE vulnerabilities occur in real-world applications
- Why input validation and secure XML parsing are critical
- How to write security-focused tests
- How to properly fix security vulnerabilities

## License

Educational purposes only. This code can serve as a security example for training purposes.
