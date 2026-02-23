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
    print("XML Document Parser - Security Validation")
    print("="*60)
    
    python_exe = sys.executable

    # Check Python version
    if not run_command(
        f"{python_exe} --version",
        "[1/3] Checking Python installation..."
    ):
        sys.exit(1)
    
    # Install dependencies
    if not run_command(
        f"{python_exe} -m pip install -q -r requirements.txt",
        "[2/3] Installing dependencies..."
    ):
        sys.exit(1)
    
    print("\n✅ Dependencies installed successfully.\n")
    
    # Run tests
    print("[3/3] Running tests...\n")
    print("Expected Results:")
    print("  - Basic functionality tests: ✅ PASS")
    print("  - XXE security tests: ✅ PASS")
    print("\nAll tests should pass. Malicious XML must not leak data.")
    print("="*60 + "\n")
    
    # Run pytest with same interpreter
    result = subprocess.run([python_exe, "-m", "pytest", "tests/", "-v", "--tb=short"])
    
    print("\n" + "="*60)
    print("Test execution completed.")
    print("\nTo re-run only security tests, use:")
    print(f"  {python_exe} -m pytest tests/test_xml_parser.py::TestXXEVulnerability -v --tb=long")
    print("\nFor more information, see KNOWN_ISSUE.md")
    print("="*60 + "\n")
    
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
