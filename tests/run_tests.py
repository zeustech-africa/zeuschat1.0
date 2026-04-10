#!/usr/bin/env python3
"""
ZeusChat Test Suite Runner
Run: python run_tests.py
"""

import subprocess
import sys
import time
from datetime import datetime


def print_header(text):
    print("\n" + "=" * 60)
    print(f" {text}")
    print("=" * 60)


def run_test(test_name):
    print(f"\n▶ Running {test_name}...")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", f"tests/{test_name}", "-v", "--tb=short"],
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    return result.returncode == 0


def main():
    print_header("ZEUSCHAT TEST SUITE")
    print(f"Started at: {datetime.now()}")

    tests = [
        "test_auth.py",
        "test_registration.py",
        "test_ghost_market.py",
        "test_ghost_community.py",
        "test_admin.py",
        "test_pin_expiry.py",
        "test_security.py",
        "test_circuit_breakers.py",
    ]

    passed = 0
    failed = 0

    for test in tests:
        if run_test(test):
            passed += 1
            print(f"✅ {test} PASSED")
        else:
            failed += 1
            print(f"❌ {test} FAILED")

    print_header("TEST SUMMARY")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total:  {len(tests)}")

    if failed == 0:
        print("\n🎉 ALL TESTS PASSED! ZeusChat is ready for launch.")
        return 0
    else:
        print("\n⚠️  Some tests failed. Please fix before launch.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
