#!/usr/bin/env python3
"""
Test runner script for API Gateway tests.

This script provides various options for running tests with different configurations.
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path


def run_command(cmd, description=""):
    """Run a command and return the result."""
    if description:
        print(f"\n🔄 {description}")
        print(f"Running: {' '.join(cmd)}")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"✅ Success: {description}")
        if result.stdout:
            print(result.stdout)
    else:
        print(f"❌ Failed: {description}")
        if result.stderr:
            print("STDERR:", result.stderr)
        if result.stdout:
            print("STDOUT:", result.stdout)
    
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description="API Gateway Test Runner")
    parser.add_argument(
        "--type",
        choices=["all", "unit", "integration", "quick"],
        default="all",
        help="Type of tests to run"
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Run tests with coverage reporting"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Run tests in verbose mode"
    )
    parser.add_argument(
        "--parallel",
        "-p",
        action="store_true",
        help="Run tests in parallel (requires pytest-xdist)"
    )
    parser.add_argument(
        "--marker",
        "-m",
        help="Run tests with specific marker (e.g., 'slow', 'network')"
    )
    parser.add_argument(
        "--file",
        "-f",
        help="Run specific test file"
    )
    parser.add_argument(
        "--function",
        "-k",
        help="Run tests matching function name pattern"
    )
    parser.add_argument(
        "--failfast",
        "-x",
        action="store_true",
        help="Stop on first failure"
    )
    parser.add_argument(
        "--no-cov",
        action="store_true",
        help="Disable coverage reporting"
    )
    parser.add_argument(
        "--html-report",
        action="store_true",
        help="Generate HTML coverage report"
    )
    parser.add_argument(
        "--install-deps",
        action="store_true",
        help="Install test dependencies before running tests"
    )
    
    args = parser.parse_args()
    
    # Change to project directory
    project_dir = Path(__file__).parent.absolute()
    os.chdir(project_dir)
    
    print(f"🧪 API Gateway Test Runner")
    print(f"📁 Working directory: {project_dir}")
    
    # Install dependencies if requested
    if args.install_deps:
        print("\n📦 Installing test dependencies...")
        if not run_command([
            sys.executable, "-m", "pip", "install", "-e", ".[dev]"
        ], "Installing development dependencies"):
            return 1
    
    # Build pytest command
    cmd = [sys.executable, "-m", "pytest"]
    
    # Add coverage options
    if not args.no_cov and (args.coverage or args.type != "quick"):
        cmd.extend([
            "--cov=app",
            "--cov-report=term-missing"
        ])
        
        if args.html_report:
            cmd.extend(["--cov-report=html:htmlcov"])
    
    # Add verbosity
    if args.verbose:
        cmd.append("-v")
    else:
        cmd.append("-q")
    
    # Add parallel execution
    if args.parallel:
        cmd.extend(["-n", "auto"])
    
    # Add fail fast
    if args.failfast:
        cmd.append("-x")
    
    # Add test type selection
    if args.type == "unit":
        cmd.extend(["-m", "unit", "tests/unit/"])
    elif args.type == "integration":
        cmd.extend(["-m", "integration", "tests/integration/"])
    elif args.type == "quick":
        cmd.extend(["-m", "not slow", "--tb=line"])
    elif args.type == "all":
        cmd.append("tests/")
    
    # Add specific marker
    if args.marker:
        cmd.extend(["-m", args.marker])
    
    # Add specific file
    if args.file:
        cmd.append(args.file)
    
    # Add function pattern
    if args.function:
        cmd.extend(["-k", args.function])
    
    # Run pre-test checks
    print("\n🔍 Running pre-test checks...")
    
    # Check if virtual environment is activated
    if not os.environ.get("VIRTUAL_ENV"):
        print("⚠️  Warning: No virtual environment detected")
        print("   Consider activating your virtual environment first")
    
    # Check if required packages are installed
    try:
        import pytest
        import fastapi
        import httpx
        print("✅ Required packages are available")
    except ImportError as e:
        print(f"❌ Missing required package: {e}")
        print("   Run with --install-deps to install dependencies")
        return 1
    
    # Create logs directory if it doesn't exist
    logs_dir = Path("tests/logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    
    # Run the tests
    print(f"\n🚀 Running tests...")
    print(f"Command: {' '.join(cmd)}")
    
    result = subprocess.run(cmd)
    
    # Print summary
    if result.returncode == 0:
        print("\n🎉 All tests passed!")
        
        # Show coverage report location if generated
        if not args.no_cov and args.html_report:
            html_report = project_dir / "htmlcov" / "index.html"
            if html_report.exists():
                print(f"📊 HTML coverage report: file://{html_report}")
    else:
        print("\n💥 Some tests failed!")
        print("Check the output above for details")
    
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
