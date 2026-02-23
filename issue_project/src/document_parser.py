"""
Document Parser Module
Handles XML document parsing for invoice and order data.

SECURITY ISSUE: This module contains a deliberate XXE vulnerability.
External entity references are NOT disabled during XML parsing.
"""

import xml.etree.ElementTree as ET
from typing import Dict, Optional
import os


class DocumentParser:
    """Parse XML documents for business data extraction."""
    
    def __init__(self):
        self.parsed_data = {}
    
    def parse_invoice(self, xml_file_path: str) -> Dict[str, str]:
        """
        Parse invoice XML file and extract business data.
        
        VULNERABILITY: Uses unsafe XML parser that allows external entity references.
        This enables XXE attacks to read arbitrary files from the system.
        
        Args:
            xml_file_path: Path to the XML file to parse
            
        Returns:
            Dictionary containing parsed invoice data
            
        Raises:
            FileNotFoundError: If XML file doesn't exist
            ET.ParseError: If XML is malformed
        """
        if not os.path.exists(xml_file_path):
            raise FileNotFoundError(f"XML file not found: {xml_file_path}")
        
        # VULNERABILITY: Unsafe XML parsing - external entities are enabled by default
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        
        # Extract invoice data
        invoice_data = {
            'id': self._get_element_text(root, 'id'),
            'customer': self._get_element_text(root, 'customer'),
            'amount': self._get_element_text(root, 'amount'),
            'date': self._get_element_text(root, 'date'),
            'status': self._get_element_text(root, 'status')
        }
        
        self.parsed_data = invoice_data
        return invoice_data
    
    def _get_element_text(self, root, tag: str) -> str:
        """Extract text from XML element."""
        element = root.find(tag)
        if element is not None:
            return element.text or ""
        return ""
    
    def get_customer_info(self) -> Optional[str]:
        """Return the customer information from the last parsed document."""
        return self.parsed_data.get('customer')
    
    def validate_and_parse(self, xml_file_path: str) -> bool:
        """
        Validate XML structure and parse if valid.
        
        Returns:
            True if parsing succeeded, False otherwise
        """
        try:
            data = self.parse_invoice(xml_file_path)
            return bool(data.get('id'))
        except Exception:
            return False


def parse_xml_document(file_path: str) -> Dict[str, str]:
    """
    Convenience function to parse XML document.
    
    VULNERABILITY: Directly exposes unsafe parsing functionality.
    """
    parser = DocumentParser()
    return parser.parse_invoice(file_path)
