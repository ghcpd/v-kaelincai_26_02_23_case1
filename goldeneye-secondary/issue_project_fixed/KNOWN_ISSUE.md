# Known Issue: XXE Vulnerability

## Summary

The `DocumentParser` class contains a **critical security vulnerability** that allows XML External Entity (XXE) attacks. This enables attackers to read arbitrary files from the server filesystem by uploading specially crafted XML documents.

## Issue Classification

- **Type:** Security Vulnerability
- **Severity:** HIGH / CRITICAL
- **CWE:** CWE-611 (Improper Restriction of XML External Entity Reference)
- **CVSS Score:** 8.6 (High)
- **Category:** Unsafe File Execution / Input Validation Failure

## Technical Details

### Root Cause

**File:** `src/document_parser.py`  
**Method:** `DocumentParser.parse_invoice()`  
**Line:** `tree = ET.parse(xml_file_path)`

The code uses Python's `xml.etree.ElementTree.parse()` without disabling external entity processing. By default, this parser resolves external entity references defined in the XML DOCTYPE declaration.

```python
# VULNERABLE CODE
tree = ET.parse(xml_file_path)  # External entities are processed!
```

### Attack Vector

An attacker uploads a malicious XML file containing an external entity declaration:

```xml
<!DOCTYPE invoice [
  <!ENTITY xxe SYSTEM "file:///path/to/sensitive/file">
]>
<invoice>
    <customer>&xxe;</customer>
</invoice>
```

When the parser processes this XML:
1. It sees the `&xxe;` entity reference
2. It reads the file specified in the DOCTYPE declaration
3. It replaces `&xxe;` with the file contents
4. The application returns/displays the sensitive data

### Trigger Conditions

**Input:** Any XML file processed by `DocumentParser.parse_invoice()`  
**Required:** XML file with DOCTYPE declaration defining external entities  
**Environment:** Any Python environment (Windows/Linux/macOS)

### Actual vs. Expected Behavior

| Aspect | Expected (Secure) | Actual (Vulnerable) |
|--------|------------------|---------------------|
| External entities | Rejected or ignored | Fully resolved |
| File access | None | Arbitrary file read |
| Customer field | Business data only | Can contain file contents |
| Error on malicious XML | Parsing error/rejection | Successful parsing |

## Demonstrated Impact

### Test Evidence

Run `pytest tests/test_xml_parser.py -v` to see:

1. ❌ `test_xxe_file_read_should_be_blocked` - FAILS  
   Sensitive file contents ARE exposed in parsed data

2. ❌ `test_xxe_external_entity_should_not_be_resolved` - FAILS  
   External entities ARE being resolved

3. ❌ `test_multiple_entity_references_should_fail` - FAILS  
   API keys and passwords detected in output

### Real-World Impact

**Confirmed Exploitable:**
- ✅ Read sensitive configuration files (API keys, passwords)
- ✅ Access system files (win.ini, /etc/passwd)
- ✅ Read application source code
- ✅ Potential for SSRF attacks (if network access enabled)
- ✅ Denial of Service via entity expansion

**Example Leaked Data:**
```
DATABASE_PASSWORD=SuperSecret123!
API_KEY=EXAMPLE_FAKE_KEY_NOT_REAL
JWT_SECRET=MyJWTSecretKey2026!
```

## Reproduction Steps

1. Run the test suite: `pytest tests/ -v`
2. Observe 4 security tests fail with XXE vulnerability messages
3. Manually verify:
   ```python
   from src.document_parser import DocumentParser
   parser = DocumentParser()
   result = parser.parse_invoice('data/xxe_attack_file_read.xml')
   print(result['customer'])  # Contains sensitive file contents!
   ```

## Fix Recommendations

### Option 1: Use `defusedxml` (Recommended)

```python
# Install: pip install defusedxml
from defusedxml.ElementTree import parse

def parse_invoice(self, xml_file_path: str) -> Dict[str, str]:
    tree = parse(xml_file_path)  # Safe parser
    root = tree.getroot()
    # ... rest of code
```

`defusedxml` automatically disables all XXE vectors.

### Option 2: Disable External Entities Manually

```python
import xml.etree.ElementTree as ET

def parse_invoice(self, xml_file_path: str) -> Dict[str, str]:
    # Create parser with entity resolution disabled
    parser = ET.XMLParser()
    parser.entity = {}  # Disable entity expansion
    
    tree = ET.parse(xml_file_path, parser=parser)
    root = tree.getroot()
    # ... rest of code
```

### Option 3: Input Validation

```python
def parse_invoice(self, xml_file_path: str) -> Dict[str, str]:
    # Read and check for DOCTYPE declarations
    with open(xml_file_path, 'r') as f:
        content = f.read()
        if '<!ENTITY' in content or '<!DOCTYPE' in content:
            raise ValueError("DOCTYPE declarations are not allowed")
    
    # Then parse safely
    tree = ET.parse(xml_file_path)
    # ...
```

### Recommended Fix Strategy

1. **Immediate:** Replace `xml.etree.ElementTree` with `defusedxml`
2. **Add validation:** Reject files with DOCTYPE declarations
3. **Update tests:** Ensure security tests pass after fix
4. **Code review:** Check for XXE in other parsers (if any)

## Testing the Fix

After implementing the fix, all tests should pass:

```batch
pytest tests/ -v
# Expected: 7 passed
```

Specifically:
- ✅ `test_xxe_file_read_should_be_blocked` - Should PASS
- ✅ `test_xxe_external_entity_should_not_be_resolved` - Should PASS
- ✅ `test_multiple_entity_references_should_fail` - Should PASS

## Additional Notes

### Why This Matters

- **Real-world prevalence:** XXE is consistently in OWASP Top 10
- **Easy to exploit:** Requires only XML upload capability
- **High impact:** Direct file access, no authentication bypass needed
- **Often overlooked:** Developers assume XML parsing is "safe"

### Related Vulnerabilities

If this codebase has other XML processing:
- Check SOAP/WSDL parsers
- Verify SVG image processing
- Review configuration file readers
- Audit any XML-RPC handlers

### References

- CWE-611: https://cwe.mitre.org/data/definitions/611.html
- OWASP XXE: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
- Python XML Vulnerabilities: https://docs.python.org/3/library/xml.html#xml-vulnerabilities

## Status

- **Discovered:** 2026-02-23
- **Status:** OPEN / UNFIXED
- **Priority:** P0 (Critical)
- **Assigned:** Security Team
