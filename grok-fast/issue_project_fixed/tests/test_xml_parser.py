"""
Tests for Document Parser - XXE Vulnerability Detection (Hardened)

These tests verify that the parser does NOT allow external entity references.
All security and basic functionality tests should PASS.
"""

import pytest
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.document_parser import DocumentParser, parse_xml_document


class TestXXEVulnerability:
    """Test cases demonstrating XXE security vulnerability (should now pass)."""
    
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
        XXE attack to read sensitive files should be blocked.
        This test verifies that external entity references are disabled.
        """
        xxe_attack_file = os.path.join(data_dir, 'xxe_attack_file_read.xml')
        with open(sensitive_file_path, 'r') as f:
            sensitive_content = f.read().strip()
        result = parser.parse_invoice(xxe_attack_file)
        customer_data = result.get('customer', '')
        assert sensitive_content not in customer_data
        assert 'API_KEY' not in customer_data
        assert 'SECRET' not in customer_data
    
    def test_xxe_external_entity_should_not_be_resolved(self, parser, data_dir):
        """
        External entities should not be resolved.
        """
        xxe_attack_file = os.path.join(data_dir, 'xxe_attack_file_read.xml')
        result = parser.parse_invoice(xxe_attack_file)
        customer_field = result.get('customer', '')
        assert not any(keyword in customer_field.upper() for keyword in 
                      ['DATABASE', 'PASSWORD', 'API', 'SECRET', 'KEY', 'TOKEN'])
    
    def test_multiple_entity_references_should_fail(self, parser, data_dir):
        """
        Documents with entity definitions should be rejected or sanitized.
        """
        xxe_attack_file = os.path.join(data_dir, 'xxe_attack_file_read.xml')
        result = parser.parse_invoice(xxe_attack_file)
        all_values = ' '.join(str(v) for v in result.values())
        dangerous_patterns = ['API_KEY', 'DB_PASSWORD', 'SECRET', '=', 'localhost', '127.0.0.1']
        for pattern in dangerous_patterns:
            assert pattern not in all_values
    
    def test_convenience_function_also_vulnerable(self, data_dir, sensitive_file_path):
        """
        The convenience function should also block XXE attacks.
        """
        xxe_attack_file = os.path.join(data_dir, 'xxe_attack_file_read.xml')
        with open(sensitive_file_path, 'r') as f:
            sensitive_content = f.read().strip()
        result = parse_xml_document(xxe_attack_file)
        customer_data = result.get('customer', '')
        assert sensitive_content not in customer_data

class TestBasicFunctionality:
    """Tests for basic, non-security functionality (should pass)."""
    
    @pytest.fixture
    def parser(self):
        return DocumentParser()
    
    @pytest.fixture
    def data_dir(self):
        return os.path.join(os.path.dirname(__file__), '..', 'data')
    
    def test_normal_invoice_has_required_fields(self, parser, data_dir):
        normal_file = os.path.join(data_dir, 'normal_invoice.xml')
        result = parser.parse_invoice(normal_file)
        assert 'id' in result
        assert 'customer' in result
        assert 'amount' in result
        assert result['id'] == 'INV-2026-001'
    
    def test_missing_file_raises_error(self, parser):
        with pytest.raises(FileNotFoundError):
            parser.parse_invoice('nonexistent_file.xml')
    
    def test_get_customer_info_returns_last_parsed(self, parser, data_dir):
        normal_file = os.path.join(data_dir, 'normal_invoice.xml')
        parser.parse_invoice(normal_file)
        customer = parser.get_customer_info()
        assert customer == 'Acme Corporation'

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
