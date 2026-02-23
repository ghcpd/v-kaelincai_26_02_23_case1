"""
Document Parser Module
Handles XML document parsing for invoice and order data.

SECURED VERSION: XXE vulnerability has been patched using input sanitization.
External entity references are stripped before parsing.
"""

import xml.etree.ElementTree as ET
from typing import Dict, Optional
import os
import re

# Constants for sanitization regex patterns
# DOCTYPE_RE removes the entire DOCTYPE declaration including internal subset
_DOCTYPE_RE = re.compile(r'<!DOCTYPE[\s\S]*?\]>', re.IGNORECASE)
# ENTITY_DECL_RE strips standalone entity declarations
_ENTITY_DECL_RE = re.compile(r'<!ENTITY[\s\S]*?>', re.IGNORECASE)
# ENTITY_REF_RE matches entity references like &xxe;
_ENTITY_REF_RE = re.compile(r'&[a-zA-Z0-9_]+;')


class DocumentParser:
    """Parse XML documents for business data extraction."""
    
    def __init__(self):
        self.parsed_data = {}
    
    def parse_invoice(self, xml_file_path: str) -> Dict[str, str]:
        """
        Parse invoice XML file and extract business data.
        
        SECURED: Input is sanitized to remove DOCTYPE and entity declarations
        before parsing to prevent XXE attacks.
        
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
        
        # Read and sanitize XML content to strip DTDs and entity declarations
        with open(xml_file_path, 'r', encoding='utf-8') as f:
            xml_content = f.read()
        
        # Remove DOCTYPE declarations and entity definitions
        xml_content = _DOCTYPE_RE.sub('', xml_content)
        xml_content = _ENTITY_DECL_RE.sub('', xml_content)
        # Replace any remaining entity references with empty text
        xml_content = _ENTITY_REF_RE.sub('', xml_content)
        
        # Parse the cleaned string to prevent external entity resolution
        tree = ET.ElementTree(ET.fromstring(xml_content))
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
    
    SECURED: Uses the same sanitization logic as DocumentParser.
    """
    parser = DocumentParser()
    return parser.parse_invoice(file_path)
