#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import tarfile
import zipfile
from pathlib import Path
import requests
import json
from urllib.parse import urlparse

ASCII_ART = """
██████╗ ███████╗██╗   ██╗███████╗██╗     ██╗ ██████╗ 
██╔══██╗██╔════╝██║   ██║██╔════╝██║     ██║██╔═══██╗
██████╔╝█████╗  ██║   ██║█████╗  ██║     ██║██║   ██║
██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║     ██║██║   ██║
██║  ██║███████╗ ╚████╔╝ ███████╗███████╗██║╚██████╔╝
╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚══════╝╚═╝ ╚═════╝ 

Package Security Scanner - Scan packages for secrets using TruffleHog

By sud0luke
"""


class PackageScanner:
    def __init__(self):
        self.temp_dir = Path("/tmp")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PackageScanner/1.0'
        })

    def scan_pypi_package(self, package_name, version=None, all_versions=False, only_verified=False,
                          no_verification=False):
        """Scan a PyPI package"""
        print(f"[INFO] Scanning PyPI package: {package_name}")

        # Get package metadata
        url = f"https://pypi.org/pypi/{package_name}/json"
        response = self.session.get(url)

        if response.status_code != 200:
            print(f"[ERROR] Failed to fetch package metadata: {response.status_code}")
            return

        data = response.json()

        if all_versions:
            versions = list(data['releases'].keys())
            print(f"[INFO] Found {len(versions)} versions")
        elif version:
            versions = [version] if version in data['releases'] else []
            if not versions:
                print(f"[ERROR] Version {version} not found")
                return
        else:
            versions = [data['info']['version']]  # Latest version

        for ver in versions:
            print(f"[INFO] Scanning version {ver}")
            releases = data['releases'][ver]

            # Find source distribution (prefer .tar.gz)
            source_url = None
            for release in releases:
                if release['packagetype'] == 'sdist':
                    source_url = release['url']
                    break

            if not source_url:
                print(f"[WARN] No source distribution found for version {ver}")
                continue

            self._download_and_scan(source_url, f"{package_name}-{ver}", only_verified, no_verification)

    def scan_npm_package(self, package_name, version=None, all_versions=False, only_verified=False,
                         no_verification=False):
        """Scan an npm package"""
        print(f"[INFO] Scanning npm package: {package_name}")

        # Handle scoped packages
        if package_name.startswith('@'):
            encoded_name = package_name.replace('/', '%2F')
        else:
            encoded_name = package_name

        # Get package metadata
        url = f"https://registry.npmjs.org/{encoded_name}"
        response = self.session.get(url)

        if response.status_code != 200:
            print(f"[ERROR] Failed to fetch package metadata: {response.status_code}")
            return

        data = response.json()

        if all_versions:
            versions = list(data['versions'].keys())
            print(f"[INFO] Found {len(versions)} versions")
        elif version:
            versions = [version] if version in data['versions'] else []
            if not versions:
                print(f"[ERROR] Version {version} not found")
                return
        else:
            versions = [data['dist-tags']['latest']]  # Latest version

        for ver in versions:
            print(f"[INFO] Scanning version {ver}")
            version_data = data['versions'][ver]
            tarball_url = version_data['dist']['tarball']

            self._download_and_scan(tarball_url, f"{package_name.replace('/', '-')}-{ver}", only_verified,
                                    no_verification)

    def _download_and_scan(self, url, package_identifier, only_verified=False, no_verification=False):
        """Download package, extract, scan with TruffleHog, and cleanup"""
        work_dir = None
        try:
            # Create temporary working directory
            work_dir = tempfile.mkdtemp(dir=self.temp_dir, prefix=f"scan_{package_identifier}_")
            work_path = Path(work_dir)

            print(f"[INFO] Downloading {url}")

            # Download the package
            response = self.session.get(url, stream=True)
            response.raise_for_status()

            # Determine file extension
            parsed_url = urlparse(url)
            filename = Path(parsed_url.path).name
            if not filename or '.' not in filename:
                # Try to determine from content-type or default to .tar.gz
                content_type = response.headers.get('content-type', '')
                if 'zip' in content_type:
                    filename = f"{package_identifier}.zip"
                else:
                    filename = f"{package_identifier}.tar.gz"

            archive_path = work_path / filename

            # Save the downloaded file
            with open(archive_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            print(f"[INFO] Extracting {filename}")

            # Extract the archive
            extract_path = work_path / "extracted"
            extract_path.mkdir()

            if filename.endswith(('.tar.gz', '.tgz', '.tar')):
                with tarfile.open(archive_path, 'r:*') as tar:
                    tar.extractall(extract_path)
            elif filename.endswith('.zip'):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
            else:
                print(f"[WARN] Unsupported archive format: {filename}")
                return

            print(f"[INFO] Running TruffleHog scan on {package_identifier}")

            # Build TruffleHog command
            trufflehog_cmd = [
                'trufflehog',
                'filesystem',
                str(extract_path),
                '--no-update'
            ]

            # Add verification flags
            if only_verified:
                trufflehog_cmd.append('--only-verified')
            elif no_verification:
                trufflehog_cmd.append('--no-verification')

            # Run TruffleHog
            result = subprocess.run(trufflehog_cmd, capture_output=True, text=True)

            if result.stdout:
                print("[RESULTS] TruffleHog Results:")
                print(result.stdout)
            else:
                print("[RESULTS] No secrets found")

            if result.stderr:
                print("[WARN] TruffleHog stderr:")
                print(result.stderr)

        except Exception as e:
            print(f"[ERROR] Error scanning {package_identifier}: {e}")
        finally:
            # Cleanup
            if work_dir and os.path.exists(work_dir):
                print(f"[INFO] Cleaning up {work_dir}")
                shutil.rmtree(work_dir)

    def check_trufflehog(self):
        """Check if TruffleHog is available"""
        try:
            result = subprocess.run(['trufflehog', '--version'],
                                    capture_output=True, text=True)
            print(f"[INFO] TruffleHog found: {result.stdout.strip()}")
            return True
        except FileNotFoundError:
            print("[ERROR] TruffleHog not found. Please install it first.")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Scan packages for secrets using TruffleHog',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan latest version of an npm package
  python scan.py --npm @babel/core

  # Scan specific version of a PyPI package
  python scan.py --pypi requests --version 2.28.1

  # Scan with only verified secrets
  python scan.py --npm lodash --only-verified

  # Scan without verification (faster, more false positives)
  python scan.py --pypi requests --no-verification

Package Ecosystems:
  --pypi      Scan Python packages from PyPI
  --npm       Scan JavaScript packages from npm (supports scoped packages like @scope/name)

Version Options:
  --version VERS      Scan a specific version
  --all-versions      Scan all available versions (use with caution!)

  If no version option is specified, scans the latest version only.

TruffleHog Options:
  --only-verified     Only report secrets that have been verified
  --no-verification   Skip verification entirely (faster but more false positives)

  If neither flag is specified, TruffleHog uses default verification behavior.
        """
    )

    # Package ecosystem
    ecosystem_group = parser.add_mutually_exclusive_group(required=True)
    ecosystem_group.add_argument('--pypi', action='store_true', help='Scan PyPI package')
    ecosystem_group.add_argument('--npm', action='store_true', help='Scan npm package')

    # Package name
    parser.add_argument('package_name', help='Package name to scan')

    # Version options
    version_group = parser.add_mutually_exclusive_group()
    version_group.add_argument('--version', help='Specific version to scan')
    version_group.add_argument('--all-versions', action='store_true',
                               help='Scan all versions of the package')

    # TruffleHog verification options
    verification_group = parser.add_mutually_exclusive_group()
    verification_group.add_argument('--only-verified', action='store_true',
                                    help='Only report verified secrets')
    verification_group.add_argument('--no-verification', action='store_true',
                                    help='Skip verification (faster, more false positives)')

    args = parser.parse_args()

    # Show ASCII art banner
    print(ASCII_ART)

    scanner = PackageScanner()

    # Check if TruffleHog is available
    if not scanner.check_trufflehog():
        sys.exit(1)

    print(f"[INFO] Starting scan for package: {args.package_name}")

    # Show verification mode
    if args.only_verified:
        print("[INFO] TruffleHog mode: Only verified secrets")
    elif args.no_verification:
        print("[INFO] TruffleHog mode: No verification (faster)")
    else:
        print("[INFO] TruffleHog mode: Default verification")

    try:
        if args.pypi:
            scanner.scan_pypi_package(args.package_name, args.version, args.all_versions,
                                      args.only_verified, args.no_verification)
        elif args.npm:
            scanner.scan_npm_package(args.package_name, args.version, args.all_versions,
                                     args.only_verified, args.no_verification)
    except KeyboardInterrupt:
        print("\n[WARN] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        sys.exit(1)

    print("[INFO] Scan completed")


if __name__ == "__main__":
    main()