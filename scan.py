#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import tarfile
import zipfile
import gzip
from pathlib import Path
import requests
import json
from urllib.parse import urlparse
import time
from datetime import datetime

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


class DiscordLogger:
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url
        self.session = requests.Session()

    def send_alert(self, package_info, secrets_found):
        """Send alert to Discord when verified secrets are found"""
        if not self.webhook_url or not secrets_found:
            return

        try:
            # Parse TruffleHog JSON output to count verified secrets
            verified_count = 0
            if secrets_found.strip():
                for line in secrets_found.strip().split('\n'):
                    try:
                        result = json.loads(line)
                        if result.get('Verified', False):
                            verified_count += 1
                    except:
                        continue

            if verified_count == 0:
                return

            embed = {
                "title": "🚨 Verified Secrets Found!",
                "color": 15158332,  # Red color
                "fields": [
                    {
                        "name": "Package",
                        "value": f"`{package_info['name']}`",
                        "inline": True
                    },
                    {
                        "name": "Ecosystem",
                        "value": package_info['ecosystem'],
                        "inline": True
                    },
                    {
                        "name": "Version",
                        "value": package_info.get('version', 'latest'),
                        "inline": True
                    },
                    {
                        "name": "Verified Secrets",
                        "value": str(verified_count),
                        "inline": True
                    }
                ],
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {
                    "text": "Package Security Scanner"
                }
            }

            payload = {
                "embeds": [embed],
                "content": f"**Alert:** Verified secrets detected in {package_info['ecosystem']} package `{package_info['name']}`"
            }

            response = self.session.post(self.webhook_url, json=payload)
            if response.status_code == 204:
                print("[INFO] Discord alert sent successfully")
            else:
                print(f"[WARN] Failed to send Discord alert: {response.status_code}")

        except Exception as e:
            print(f"[WARN] Discord logging error: {e}")


class PackageScanner:
    def __init__(self, discord_webhook=None):
        self.temp_dir = Path("/tmp")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PackageScanner/1.0'
        })
        self.discord_logger = DiscordLogger(discord_webhook)

    def scan_from_file(self, file_path, ecosystem, version=None, all_versions=False, 
                      only_verified=False, no_verification=False, delay=1.0):
        """Scan packages listed in a text file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                package_names = [line.strip() for line in f if line.strip()]
            
            print(f"[INFO] Found {len(package_names)} packages to scan from {file_path}")
            
            for i, package_name in enumerate(package_names, 1):
                print(f"[INFO] Scanning package {i}/{len(package_names)}: {package_name}")
                
                if ecosystem == 'pypi':
                    self.scan_pypi_package(package_name, version, all_versions, only_verified, no_verification)
                elif ecosystem == 'npm':
                    self.scan_npm_package(package_name, version, all_versions, only_verified, no_verification)
                elif ecosystem == 'crates':
                    self.scan_crates_package(package_name, version, all_versions, only_verified, no_verification)
                
                # Rate limiting between requests
                if i < len(package_names):
                    print(f"[INFO] Waiting {delay}s before next package...")
                    time.sleep(delay)
                    
        except FileNotFoundError:
            print(f"[ERROR] File not found: {file_path}")
        except Exception as e:
            print(f"[ERROR] Error reading file {file_path}: {e}")

    def scan_crates_package(self, package_name, version=None, all_versions=False, only_verified=False,
                           no_verification=False):
        """Scan a Rust crate from crates.io"""
        print(f"[INFO] Scanning Rust crate: {package_name}")

        # Get crate metadata
        url = f"https://crates.io/api/v1/crates/{package_name}"
        response = self.session.get(url)

        if response.status_code != 200:
            print(f"[ERROR] Failed to fetch crate metadata: {response.status_code}")
            return

        data = response.json()
        crate_info = data['crate']

        if all_versions:
            # Get all versions
            versions_url = f"https://crates.io/api/v1/crates/{package_name}/versions"
            versions_response = self.session.get(versions_url)
            if versions_response.status_code == 200:
                versions_data = versions_response.json()
                versions = [v['num'] for v in versions_data['versions']]
                print(f"[INFO] Found {len(versions)} versions")
            else:
                versions = [crate_info['newest_version']]
        elif version:
            versions = [version]
        else:
            versions = [crate_info['newest_version']]  # Latest version

        for ver in versions:
            print(f"[INFO] Scanning version {ver}")
            
            # Download URL for .crate file
            download_url = f"https://crates.io/api/v1/crates/{package_name}/{ver}/download"
            
            package_info = {
                'name': package_name,
                'version': ver,
                'ecosystem': 'crates.io'
            }
            
            self._download_and_scan(download_url, f"{package_name}-{ver}", only_verified, 
                                  no_verification, package_info, is_crate=True)

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

            package_info = {
                'name': package_name,
                'version': ver,
                'ecosystem': 'PyPI'
            }

            self._download_and_scan(source_url, f"{package_name}-{ver}", only_verified, 
                                  no_verification, package_info)

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

            package_info = {
                'name': package_name,
                'version': ver,
                'ecosystem': 'npm'
            }

            self._download_and_scan(tarball_url, f"{package_name.replace('/', '-')}-{ver}", 
                                  only_verified, no_verification, package_info)

    def _download_and_scan(self, url, package_identifier, only_verified=False, no_verification=False, 
                          package_info=None, is_crate=False):
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
            if is_crate:
                filename = f"{package_identifier}.crate"
            else:
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

            if filename.endswith('.crate') or filename.endswith(('.tar.gz', '.tgz', '.tar')):
                # .crate files are gzipped tarballs
                with tarfile.open(archive_path, 'r:gz') as tar:
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
                '--no-update',
                '--json'  # JSON output for parsing
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
                
                # Send Discord alert if verified secrets found
                if package_info:
                    self.discord_logger.send_alert(package_info, result.stdout)
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
  # Scan latest version of packages
  python scan.py --npm @babel/core
  python scan.py --pypi requests
  python scan.py --crates serde

  # Scan specific version
  python scan.py --pypi requests --version 2.28.1

  # Scan from file (works with all ecosystems)
  python scan.py --crates --file crate_names.txt
  python scan.py --pypi --file python_packages.txt
  python scan.py --npm --file npm_packages.txt

  # Scan with Discord alerts
  python scan.py --npm lodash --discord-webhook https://discord.com/api/webhooks/...

  # Scan with rate limiting
  python scan.py --pypi --file packages.txt --delay 2.0

Package Ecosystems:
  --pypi      Scan Python packages from PyPI
  --npm       Scan JavaScript packages from npm (supports scoped packages)
  --crates    Scan Rust crates from crates.io

Input Options:
  package_name        Single package name to scan
  --file FILE         Scan packages listed in text file (one per line) - works with all ecosystems

Version Options:
  --version VERS      Scan a specific version
  --all-versions      Scan all available versions (use with caution!)

TruffleHog Options:
  --only-verified     Only report secrets that have been verified
  --no-verification   Skip verification entirely (faster but more false positives)

Batch Processing:
  --delay SECONDS     Delay between packages when scanning from file (default: 1.0)

Discord Integration:
  --discord-webhook URL   Discord webhook URL for alerts when verified secrets found
        """
    )

    # Package ecosystem
    ecosystem_group = parser.add_mutually_exclusive_group(required=True)
    ecosystem_group.add_argument('--pypi', action='store_true', help='Scan PyPI package')
    ecosystem_group.add_argument('--npm', action='store_true', help='Scan npm package')
    ecosystem_group.add_argument('--crates', action='store_true', help='Scan Rust crates')

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('package_name', nargs='?', help='Package name to scan')
    input_group.add_argument('--file', help='Text file containing package names (one per line)')

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

    # Batch processing options
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Delay between packages when scanning from file (seconds)')

    # Discord integration
    parser.add_argument('--discord-webhook', help='Discord webhook URL for alerts')

    args = parser.parse_args()

    # Validate arguments
    if not args.package_name and not args.file:
        parser.error('Either package_name or --file is required')

    # Show ASCII art banner
    print(ASCII_ART)

    scanner = PackageScanner(args.discord_webhook)

    # Check if TruffleHog is available
    if not scanner.check_trufflehog():
        sys.exit(1)

    # Determine ecosystem
    ecosystem = 'pypi' if args.pypi else 'npm' if args.npm else 'crates'

    # Show configuration
    if args.file:
        print(f"[INFO] Batch scanning from file: {args.file}")
        print(f"[INFO] Ecosystem: {ecosystem}")
        print(f"[INFO] Delay between packages: {args.delay}s")
    else:
        print(f"[INFO] Starting scan for package: {args.package_name}")
        print(f"[INFO] Ecosystem: {ecosystem}")

    # Show verification mode
    if args.only_verified:
        print("[INFO] TruffleHog mode: Only verified secrets")
    elif args.no_verification:
        print("[INFO] TruffleHog mode: No verification (faster)")
    else:
        print("[INFO] TruffleHog mode: Default verification")

    if args.discord_webhook:
        print("[INFO] Discord alerts enabled for verified secrets")

    try:
        if args.file:
            scanner.scan_from_file(args.file, ecosystem, args.version, args.all_versions,
                                 args.only_verified, args.no_verification, args.delay)
        else:
            if args.pypi:
                scanner.scan_pypi_package(args.package_name, args.version, args.all_versions,
                                        args.only_verified, args.no_verification)
            elif args.npm:
                scanner.scan_npm_package(args.package_name, args.version, args.all_versions,
                                       args.only_verified, args.no_verification)
            elif args.crates:
                scanner.scan_crates_package(args.package_name, args.version, args.all_versions,
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