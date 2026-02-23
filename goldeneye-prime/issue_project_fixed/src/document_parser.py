"""
Document Parser Module
Handles XML document parsing for invoice and order data.

SECURITY-FIXED: Hardened against XXE (XML External Entity) attacks.
- External entity resolution is disabled
- Documents containing DTD/ENTITY declarations are rejected
- Optional `defusedxml` integration for defense-in-depth
"""

from typing import Dict, Optional
import os
import io
import re
import xml.etree.ElementTree as ET

try:  # Prefer hardened parser if available
    from defusedxml import ElementTree as DefusedET  # type: ignore
    _HAS_DEFUSEDXML = True
except Exception:  # pragma: no cover - dependency optional
    DefusedET = None  # type: ignore
    _HAS_DEFUSEDXML = False


class XMLSecurityError(ValueError):
    """Raised when an XML document violates security policy (e.g., DTD detected)."""


class DocumentParser:
    """Parse XML documents for business data extraction."""
    
    def __init__(self):
        self.parsed_data = {}
    
    def parse_invoice(self, xml_file_path: str) -> Dict[str, str]:
        """
        Parse invoice XML file and extract business data.

        Args:
            xml_file_path: Path to the XML file to parse

        Returns:
            Dictionary containing parsed invoice data

        Raises:
            FileNotFoundError: If XML file doesn't exist
            XMLSecurityError | ET.ParseError: If XML is malformed or violates policy
        """
        if not os.path.exists(xml_file_path):
            raise FileNotFoundError(f"XML file not found: {xml_file_path}")

        try:
            root = self._parse_xml_secure(xml_file_path)
        except XMLSecurityError:
            # Security policy violation => return safe empty payload
            self.parsed_data = {}
            return {}
        except Exception:
            # Parsing errors should not expose data
            self.parsed_data = {}
            return {}

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
    
    # Internal API -----------------------------------------------------
    def _parse_xml_secure(self, xml_file_path: str):
        """
        Parse XML safely, blocking XXE vectors.

        Strategy:
        - Pre-scan the raw document for DTD/ENTITY declarations and reject
        - Prefer `defusedxml` if installed; fall back to stdlib with entity resolution disabled
        """
        raw_bytes = self._read_file_bytes(xml_file_path)
        self._guard_against_dtd(raw_bytes)

        if _HAS_DEFUSEDXML:
            # defusedxml raises DefusedXmlException on dangerous constructs
            # Use BytesIO to avoid re-reading from disk
            tree = DefusedET.parse(io.BytesIO(raw_bytes))
            return tree.getroot()

        # Fallback: disable entity resolution with stdlib parser
        parser = ET.XMLParser(resolve_entities=False)
        # Using fromstring ensures we control parser settings
        root = ET.fromstring(raw_bytes, parser=parser)
        return root

    @staticmethod
    def _read_file_bytes(path: str) -> bytes:
        with open(path, 'rb') as fh:
            return fh.read()

    @staticmethod
    def _guard_against_dtd(raw: bytes) -> None:
        # Case-insensitive detection of any DOCTYPE/ENTITY declarations
        # Reject early to avoid even attempting to parse malicious content
        upper = raw.upper()
        if b'<!DOCTYPE' in upper or b'<!ENTITY' in upper or b'<!ATTLIST' in upper:
            raise XMLSecurityError("DTD/ENTITY declarations are not allowed.")

        # Also guard against parameter entities often denoted by '%'
        # Use a simple regex to detect patterns like `<!ENTITY % ...>`
        dtd_pattern = re.compile(br'<!\s*ENTITY\s+%|<!\s*DOCTYPE', re.IGNORECASE)
        if dtd_pattern.search(raw):
            raise XMLSecurityError("DTD/ENTITY declarations are not allowed.")

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

    This reuses the same hardened parsing logic used by `DocumentParser`.
    """
    parser = DocumentParser()
    return parser.parse_invoice(file_path)
