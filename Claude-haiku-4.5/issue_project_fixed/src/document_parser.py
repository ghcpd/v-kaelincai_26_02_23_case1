"""
Document Parser Module
Handles XML document parsing for invoice and order data.

SECURITY FIX: This module has been secured against XXE vulnerabilities.
External entity references are disabled during XML parsing.
"""

from defusedxml.ElementTree import parse as safe_parse
from defusedxml.common import EntitiesForbidden
from typing import Dict, Optional
import os


class DocumentParser:
    """Parse XML documents for business data extraction."""
    
    def __init__(self):
        self.parsed_data = {}
    
    def parse_invoice(self, xml_file_path: str) -> Dict[str, str]:
        """
        Parse invoice XML file and extract business data.
        
        SECURITY: Uses defusedxml to safely parse XML without external entity resolution.
        This prevents XXE attacks that could read arbitrary files from the system.
        
        Args:
            xml_file_path: Path to the XML file to parse
            
        Returns:
            Dictionary containing parsed invoice data
            
        Raises:
            FileNotFoundError: If XML file doesn't exist
            ParseError: If XML is malformed or contains unsafe content
        """
        if not os.path.exists(xml_file_path):
            raise FileNotFoundError(f"XML file not found: {xml_file_path}")
        
        # SECURITY FIX: Use defusedxml.ElementTree.parse instead of standard ElementTree.parse
        # This automatically disables external entity resolution and prevents XXE attacks
        try:
            tree = safe_parse(xml_file_path)
            root = tree.getroot()
        except EntitiesForbidden:
            # Entity definition detected and blocked by defusedxml
            # Return safe default data without external entity content
            invoice_data = {
                'id': '',
                'customer': '',
                'amount': '',
                'date': '',
                'status': ''
            }
            self.parsed_data = invoice_data
            return invoice_data
        
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
    Convenience function to parse XML document safely.
    
    SECURITY: Uses defusedxml to prevent XXE attacks.
    """
    parser = DocumentParser()
    return parser.parse_invoice(file_path)
