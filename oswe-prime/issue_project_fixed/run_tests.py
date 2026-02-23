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
    print("XML Document Parser - SECURED VERSION Test Runner")
    print("="*60)
    
    # Check Python version
    if not run_command(
        "python --version",
        "[1/2] Checking Python installation..."
    ):
        sys.exit(1)
    
    print("\n[2/2] Running built-in validation checks...\n")
    
    from src.document_parser import DocumentParser, parse_xml_document
    
    failures = []
    
    def assert_true(cond, msg):
        if not cond:
            failures.append(msg)
    
    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    sensitive_file = os.path.join(data_dir, 'sensitive', 'secret_config.txt')
    
    parser = DocumentParser()
    
    # Basic functionality tests
    print("Testing basic functionality...")
    normal_file = os.path.join(data_dir, 'normal_invoice.xml')
    try:
        res = parser.parse_invoice(normal_file)
        assert_true(res.get('id') == 'INV-2026-001', 'normal invoice id mismatch')
        assert_true(res.get('customer') == 'Acme Corporation', 'normal customer mismatch')
        print("  ✅ Normal XML parsing works")
    except Exception as e:
        failures.append(f'basic parsing raised {e}')
        print(f"  ❌ Normal XML parsing failed: {e}")
    
    try:
        parser.parse_invoice('nonexistent_file.xml')
        failures.append('missing file did not raise')
        print("  ❌ Missing file error handling failed")
    except FileNotFoundError:
        print("  ✅ Missing file error handling works")
    
    parser.parse_invoice(normal_file)
    if parser.get_customer_info() == 'Acme Corporation':
        print("  ✅ get_customer_info works")
    else:
        assert_true(False, 'get_customer_info incorrect')
        print("  ❌ get_customer_info failed")
    
    # Security tests
    print("\nTesting XXE security...")
    xxe_file = os.path.join(data_dir, 'xxe_attack_file_read.xml')
    with open(sensitive_file, 'r') as f:
        sensitive_contents = f.read().strip()
    
    try:
        sec_res = parser.parse_invoice(xxe_file)
        cust = sec_res.get('customer', '')
        assert_true(sensitive_contents not in cust, 'sensitive content leaked')
        assert_true('API_KEY' not in cust, 'API_KEY leaked')
        assert_true('SECRET' not in cust, 'SECRET leaked')
        assert_true(not any(k in cust.upper() for k in ['DATABASE', 'PASSWORD',
                                                        'API', 'KEY', 'TOKEN']),
                    'external entity was resolved')
        allvals = ' '.join(str(v) for v in sec_res.values())
        for pat in ['API_KEY', 'DB_PASSWORD', 'SECRET', '=', 'localhost', '127.0.0.1']:
            assert_true(pat not in allvals, f"pattern '{pat}' found")
        print("  ✅ XXE file read attack blocked")
    except Exception as e:
        failures.append(f'security parsing raised {e}')
        print(f"  ❌ XXE security test failed: {e}")
    
    # Convenience function check
    try:
        cf_res = parse_xml_document(xxe_file)
        assert_true(sensitive_contents not in cf_res.get('customer', ''),
                    'convenience function leaked data')
        print("  ✅ Convenience function is secure")
    except Exception as e:
        failures.append(f'convenience function error {e}')
        print(f"  ❌ Convenience function test failed: {e}")
    
    print('\n' + '='*60)
    if failures:
        print('❌ Some checks failed:')
        for f in failures:
            print(' -', f)
        print('='*60)
        return 1
    else:
        print('✅ All checks passed. Parser is now safe.')
        print('='*60)
        return 0


if __name__ == "__main__":
    sys.exit(main())
