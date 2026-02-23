"""
Tests for Document Parser - XXE Vulnerability Detection

These tests are designed to FAIL and demonstrate the XXE vulnerability.
The tests verify that the parser does NOT allow external entity references,
but the current implementation DOES allow them (hence the tests fail).
"""

import pytest
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.document_parser import DocumentParser, parse_xml_document


class TestXXEVulnerability:
    """Test cases demonstrating XXE security vulnerability."""
    
    @pytest.fixture
    def parser(self):
        """Create a DocumentParser instance."""
        return DocumentParser()
    
    @pytest.fixture
    def data_dir(self):
        """Get the data directory path."""
        return os.path.join(os.path.dirname(__file__), '..', 'data')
    
    @pytest.fixture
    def sensitive_file_path(self):
        """Path to sensitive configuration file."""
        return os.path.join(os.path.dirname(__file__), '..', 'data', 'sensitive', 'secret_config.txt')
    
    def test_normal_invoice_parsing(self, parser, data_dir):
        """Test that normal invoice files are parsed correctly."""
        normal_file = os.path.join(data_dir, 'normal_invoice.xml')
        result = parser.parse_invoice(normal_file)
        
        assert result['id'] == 'INV-2026-001'
        assert result['customer'] == 'Acme Corporation'
        assert result['amount'] == '5000.00'
    
    def test_xxe_file_read_should_be_blocked(self, parser, data_dir, sensitive_file_path):
        """
        TEST FAILURE EXPECTED: XXE attack to read sensitive files should be blocked.
        
        This test verifies that external entity references are disabled.
        CURRENT BEHAVIOR: The parser allows XXE and reads the sensitive file.
        EXPECTED BEHAVIOR: The parser should reject external entities or return safe content.
        
        The test will FAIL because the sensitive content IS exposed in the parsed data.
        """
        xxe_attack_file = os.path.join(data_dir, 'xxe_attack_file_read.xml')
        
        # Read what the sensitive file actually contains
        with open(sensitive_file_path, 'r') as f:
            sensitive_content = f.read().strip()
        
        # Parse the malicious XML
        result = parser.parse_invoice(xxe_attack_file)
        customer_data = result.get('customer', '')
        
        # ASSERTION: Sensitive content should NOT be in the parsed data
        # This test FAILS because XXE vulnerability allows file reading
        assert sensitive_content not in customer_data, \
            f"XXE VULNERABILITY DETECTED: Sensitive file content was exposed in customer field. " \
            f"Found: '{customer_data[:100]}...'"
        
        # Additional check: customer field should contain expected safe data
        assert 'API_KEY' not in customer_data, \
            "XXE VULNERABILITY: API_KEY from sensitive file was leaked"
        assert 'SECRET' not in customer_data, \
            "XXE VULNERABILITY: SECRET from sensitive file was leaked"
    
    def test_xxe_external_entity_should_not_be_resolved(self, parser, data_dir):
        """
        TEST FAILURE EXPECTED: External entities should not be resolved.
        
        When an XML contains external entity references, the parser should either:
        1. Reject the document, or
        2. Treat the entity reference as literal text
        
        CURRENT BEHAVIOR: External entities ARE resolved and file content is exposed.
        EXPECTED BEHAVIOR: Entity references should be blocked or ignored.
        """
        xxe_attack_file = os.path.join(data_dir, 'xxe_attack_file_read.xml')
        result = parser.parse_invoice(xxe_attack_file)
        
        customer_field = result.get('customer', '')
        
        # Check if the content suggests external entity was resolved
        # The entity should NOT be replaced with actual file content
        assert not any(keyword in customer_field.upper() for keyword in 
                      ['DATABASE', 'PASSWORD', 'API', 'SECRET', 'KEY', 'TOKEN']), \
            f"XXE VULNERABILITY: External entity was resolved. Customer field contains: {customer_field[:200]}"
    
    def test_multiple_entity_references_should_fail(self, parser, data_dir):
        """
        TEST FAILURE EXPECTED: Documents with entity definitions should be rejected or sanitized.
        
        This test uses a different XXE payload to verify the vulnerability exists.
        """
        xxe_attack_file = os.path.join(data_dir, 'xxe_attack_file_read.xml')
        
        # The parser should either throw an error or return safe data
        result = parser.parse_invoice(xxe_attack_file)
        
        # Check all fields for leaked sensitive information
        all_values = ' '.join(str(v) for v in result.values())
        
        # These patterns indicate successful XXE exploitation
        dangerous_patterns = ['API_KEY', 'DB_PASSWORD', 'SECRET', '=', 'localhost', '127.0.0.1']
        
        for pattern in dangerous_patterns:
            assert pattern not in all_values, \
                f"XXE VULNERABILITY: Pattern '{pattern}' found in parsed data, indicating file read success"
    
    def test_convenience_function_also_vulnerable(self, data_dir, sensitive_file_path):
        """
        TEST FAILURE EXPECTED: The convenience function should also block XXE attacks.
        """
        xxe_attack_file = os.path.join(data_dir, 'xxe_attack_file_read.xml')
        
        # Read sensitive content
        with open(sensitive_file_path, 'r') as f:
            sensitive_content = f.read().strip()
        
        result = parse_xml_document(xxe_attack_file)
        customer_data = result.get('customer', '')
        
        # Verify sensitive data is NOT exposed
        assert sensitive_content not in customer_data, \
            "XXE VULNERABILITY in parse_xml_document: Sensitive data was exposed"


class TestBasicFunctionality:
    """Tests for basic, non-security functionality (these should pass)."""
    
    @pytest.fixture
    def parser(self):
        return DocumentParser()
    
    @pytest.fixture
    def data_dir(self):
        return os.path.join(os.path.dirname(__file__), '..', 'data')
    
    def test_normal_invoice_has_required_fields(self, parser, data_dir):
        """Verify normal invoice parsing works correctly."""
        normal_file = os.path.join(data_dir, 'normal_invoice.xml')
        result = parser.parse_invoice(normal_file)
        
        assert 'id' in result
        assert 'customer' in result
        assert 'amount' in result
        assert result['id'] == 'INV-2026-001'
    
    def test_missing_file_raises_error(self, parser):
        """Verify appropriate error for missing files."""
        with pytest.raises(FileNotFoundError):
            parser.parse_invoice('nonexistent_file.xml')
    
    def test_get_customer_info_returns_last_parsed(self, parser, data_dir):
        """Verify customer info retrieval works."""
        normal_file = os.path.join(data_dir, 'normal_invoice.xml')
        parser.parse_invoice(normal_file)
        
        customer = parser.get_customer_info()
        assert customer == 'Acme Corporation'


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

