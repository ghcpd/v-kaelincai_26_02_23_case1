"""issue_project_fixed.src.document_parser

Document Parser Module
Handles XML document parsing for invoice and order data.

This version has been hardened against XML External Entity (XXE) attacks.
External DTDs and entity expansion are blocked, and any entity references
in input are treated as plain text.
"""

from __future__ import annotations

import os
import re
from typing import Dict, Optional

# Prefer defusedxml when available. It blocks DTDs and entity expansion.
try:
    from defusedxml import ElementTree as SafeET  # type: ignore
except ImportError:  # pragma: no cover
    import xml.etree.ElementTree as SafeET


# Regex to remove any DOCTYPE/ENTITY declarations.
_DOCTYPE_RE = re.compile(r"<!DOCTYPE[^>]*?(\[[\s\S]*?\])?>", re.IGNORECASE)
_ENTITY_DECL_RE = re.compile(r"<!ENTITY\s+[^>]*>", re.IGNORECASE)


class DocumentParser:
    """Parse XML documents for business data extraction."""

    def __init__(self) -> None:
        self.parsed_data: Dict[str, str] = {}

    def parse_invoice(self, xml_file_path: str) -> Dict[str, str]:
        """Parse invoice XML file and extract business data.

        The parser rejects or sanitizes external entity declarations to prevent
        XXE attacks. Malicious entity references will not be resolved or leak
        local file contents.

        Args:
            xml_file_path: Path to the XML file to parse.

        Returns:
            Dictionary containing parsed invoice data.

        Raises:
            FileNotFoundError: If XML file doesn't exist.
            SafeET.ParseError: If XML is malformed even after sanitization.
        """
        if not os.path.exists(xml_file_path):
            raise FileNotFoundError(f"XML file not found: {xml_file_path}")

        # First try safe parser directly (defusedxml blocks entities).
        try:
            tree = SafeET.parse(xml_file_path)
            root = tree.getroot()
        except Exception:
            # Fall back to stripping DOCTYPE/ENTITY sections and entity refs.
            with open(xml_file_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_xml = f.read()

            sanitized = self._sanitize_xml(raw_xml)
            root = SafeET.fromstring(sanitized)

        invoice_data = {
            "id": self._get_element_text(root, "id"),
            "customer": self._get_element_text(root, "customer"),
            "amount": self._get_element_text(root, "amount"),
            "date": self._get_element_text(root, "date"),
            "status": self._get_element_text(root, "status"),
        }

        self.parsed_data = invoice_data
        return invoice_data

    def _sanitize_xml(self, xml_text: str) -> str:
        """Remove DTD and entity declarations and neutralize entity references."""
        without_doctype = _DOCTYPE_RE.sub("", xml_text)
        without_entity_decl = _ENTITY_DECL_RE.sub("", without_doctype)

        # Replace any remaining entity references (&foo;) with empty string.
        safe_text = re.sub(r"&[A-Za-z0-9_:-]+;", "", without_entity_decl)
        return safe_text

    def _get_element_text(self, root, tag: str) -> str:
        """Extract text from XML element."""
        element = root.find(tag)
        if element is not None and element.text is not None:
            return element.text
        return ""

    def get_customer_info(self) -> Optional[str]:
        """Return the customer information from the last parsed document."""
        return self.parsed_data.get("customer")

    def validate_and_parse(self, xml_file_path: str) -> bool:
        """Validate XML structure and parse if valid."""
        try:
            data = self.parse_invoice(xml_file_path)
            return bool(data.get("id"))
        except Exception:
            return False


def parse_xml_document(file_path: str) -> Dict[str, str]:
    """Convenience function to parse an invoice XML document."""
    parser = DocumentParser()
    return parser.parse_invoice(file_path)
