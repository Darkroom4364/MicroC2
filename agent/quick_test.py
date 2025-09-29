#!/usr/bin/env python3
"""
Quick Development Test Script for MicroC2 Agent

This is a lightweight companion to the comprehensive test suite, designed for
rapid iteration during development. It focuses on the most critical tests
that developers need to run frequently.

Usage:
    python quick_test.py [--build] [--crypto] [--verbose]
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

class QuickTest:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.agent_path = Path(__file__).parent
        
    def log(self, message, success=None):
        """Simple logging with color coding"""
        if success is True:
            prefix = "✅"
        elif success is False:
            prefix = "❌"
        else:
            prefix = "ℹ️"
        
        print(f"{prefix} {message}")
        
    def run_command(self, cmd, timeout=60):
        """Run command and return success status"""
        try:
            if self.verbose:
                self.log(f"Running: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                cwd=self.agent_path,
                capture_output=not self.verbose,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                if self.verbose and result.stdout:
                    print(result.stdout)
                return True, result.stdout, result.stderr
            else:
                if result.stderr:
                    print(result.stderr)
                return False, result.stdout, result.stderr
                
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out after {timeout}s", False)
            return False, "", "Timeout"
        except Exception as e:
            self.log(f"Command failed: {e}", False)
            return False, "", str(e)
    
    def test_crypto(self):
        """Quick crypto tests"""
        self.log("Testing cryptographic functions...")
        
        success, stdout, stderr = self.run_command([
            "cargo", "test", "test_key_derivation", 
            "--features", "encryption-chacha", "--", "--nocapture"
        ])
        
        if success and stdout and "test result: ok" in stdout:
            self.log("Crypto tests passed", True)
            return True
        else:
            self.log("Crypto tests failed", False)
            if stderr and not self.verbose:
                print(f"Error: {stderr}")
            return False
    
    def test_build(self):
        """Quick build test"""
        self.log("Testing build...")
        
        # Check compilation
        success, stdout, stderr = self.run_command([
            "cargo", "check", "--features", "encryption-chacha"
        ], timeout=30)
        
        if success:
            self.log("Build check passed", True)
            
            # Quick release build test
            self.log("Testing release build...")
            success, stdout, stderr = self.run_command([
                "cargo", "build", "--release", "--features", "encryption-chacha"
            ], timeout=120)
            
            if success:
                # Check binary size
                binary_path = self.agent_path / "target" / "release" / "agent"
                if binary_path.exists():
                    size_mb = binary_path.stat().st_size / (1024 * 1024)
                    self.log(f"Release build successful ({size_mb:.1f}MB)", True)
                    return True
                else:
                    self.log("Binary not found after build", False)
                    return False
            else:
                self.log("Release build failed", False)
                if stderr and not self.verbose:
                    print(f"Error: {stderr}")
                return False
        else:
            self.log("Build check failed", False)
            if stderr and not self.verbose:
                print(f"Error: {stderr}")
            return False
    
    def test_unit_tests(self):
        """Run all unit tests"""
        self.log("Running unit tests...")
        
        success, stdout, stderr = self.run_command([
            "cargo", "test", "--features", "encryption-chacha"
        ])
        
        if success and stdout and "test result: ok" in stdout:
            # Extract test count
            lines = stdout.split('\n')
            for line in lines:
                if "test result:" in line and "passed" in line:
                    self.log(f"Unit tests: {line.strip()}", True)
                    break
            else:
                self.log("Unit tests passed", True)
            return True
        else:
            self.log("Some unit tests failed", False)
            if stderr and not self.verbose:
                print(f"Error: {stderr}")
            return False
    
    def run_quick_tests(self, include_build=False, include_crypto=False):
        """Run the quick test suite"""
        print("🚀 MicroC2 Agent Quick Test Suite")
        print("=" * 40)
        
        start_time = time.time()
        tests_run = 0
        tests_passed = 0
        
        # Always run unit tests
        tests_run += 1
        if self.test_unit_tests():
            tests_passed += 1
        
        # Crypto tests if requested
        if include_crypto:
            tests_run += 1
            if self.test_crypto():
                tests_passed += 1
        
        # Build tests if requested
        if include_build:
            tests_run += 1
            if self.test_build():
                tests_passed += 1
        
        # Summary
        duration = time.time() - start_time
        print("\n" + "=" * 40)
        
        if tests_passed == tests_run:
            self.log(f"All {tests_run} tests passed in {duration:.1f}s", True)
            return True
        else:
            self.log(f"{tests_passed}/{tests_run} tests passed in {duration:.1f}s", False)
            return False

def main():
    parser = argparse.ArgumentParser(
        description="Quick development tests for MicroC2 Agent"
    )
    
    parser.add_argument(
        '--build', '-b',
        action='store_true',
        help='Include build tests (slower)'
    )
    
    parser.add_argument(
        '--crypto', '-c',
        action='store_true',
        help='Include detailed crypto tests'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    tester = QuickTest(verbose=args.verbose)
    
    try:
        success = tester.run_quick_tests(
            include_build=args.build,
            include_crypto=args.crypto
        )
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Test execution failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()