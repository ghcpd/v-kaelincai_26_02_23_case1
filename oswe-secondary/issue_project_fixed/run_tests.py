#!/usr/bin/env python3
"""
Cross-platform test runner for XXE vulnerability demonstration.
Use this script on Linux/macOS or if you prefer Python to batch files.
"""

import subprocess
import sys
import os


def run_command(cmd, description):
    """Run a command and handle errors."""
    print(f"\n{'='*60}")
    print(f"{description}")
    print('='*60)
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"\n❌ ERROR: {description} failed")
        return False
    return True


def main():
    print("\n" + "="*60)
    print("XML Document Parser - XXE Vulnerability Tests")
    print("="*60)
    
    # Check Python version
    if not run_command(
        "python --version",
        "[1/3] Checking Python installation..."
    ):
        sys.exit(1)
    
    # Install dependencies
    if not run_command(
        "pip install -q -r requirements.txt",
        "[2/3] Installing dependencies..."
    ):
        sys.exit(1)
    
    print("\n✅ Dependencies installed successfully.\n")
    
    # Run tests
    print("[3/3] Running tests...\n")
    print("Expected Results:")
    print("  - Basic functionality tests: ✅ PASS (3 tests)")
    print("  - XXE security tests: ❌ FAIL (4 tests)")
    print("\nThe failing tests demonstrate the XXE vulnerability.")
    print("="*60 + "\n")
    
    # Run pytest
    result = subprocess.run(["pytest", "tests/", "-v", "--tb=short"])
    
    print("\n" + "="*60)
    print("Test execution completed.")
    print("\nTo see detailed vulnerability analysis, run:")
    print("  pytest tests/test_xml_parser.py::TestXXEVulnerability -v --tb=long")
    print("\nFor more information, see KNOWN_ISSUE.md")
    print("="*60 + "\n")
    
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
