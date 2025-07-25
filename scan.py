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
                elif ecosystem == 'maven':
                    self.scan_maven_package(package_name, version, all_versions, only_verified, no_verification)
                
                # Rate limiting between requests
                if i < len(package_names):
                    print(f"[INFO] Waiting {delay}s before next package...")
                    time.sleep(delay)
                    
        except FileNotFoundError:
            print(f"[ERROR] File not found: {file_path}")
        except Exception as e:
            print(f"[ERROR] Error reading file {file_path}: {e}")

    def scan_maven_package(self, package_name, version=None, all_versions=False, only_verified=False,
                          no_verification=False):
        """Scan a Maven package from Maven Central"""
        print(f"[INFO] Scanning Maven package: {package_name}")
        
        # Parse group_id:artifact_id format
        if ':' not in package_name:
            print("[ERROR] Maven package name must be in format 'group_id:artifact_id'")
            return
        
        group_id, artifact_id = package_name.split(':', 1)
        print(f"[INFO] Group ID: {group_id}, Artifact ID: {artifact_id}")
        
        if all_versions:
            # Get all versions using Maven Central Search API
            versions = self._get_all_maven_versions(group_id, artifact_id)
            if not versions:
                print("[ERROR] No versions found")
                return
            print(f"[INFO] Found {len(versions)} versions")
        elif version:
            versions = [version]
        else:
            # Get latest version
            latest_version = self._get_latest_maven_version(group_id, artifact_id)
            if not latest_version:
                print("[ERROR] Could not determine latest version")
                return
            versions = [latest_version]
        
        for ver in versions:
            print(f"[INFO] Scanning version {ver}")
            
            package_info = {
                'name': package_name,
                'version': ver,
                'ecosystem': 'Maven Central'
            }
            
            # Try to download different artifact types (JAR, sources, etc.)
            self._scan_maven_artifacts(group_id, artifact_id, ver, package_info, 
                                     only_verified, no_verification)

    def _get_all_maven_versions(self, group_id, artifact_id):
        """Get all versions for a Maven artifact"""
        try:
            # Use Maven Central Search API to get all versions
            search_url = "https://search.maven.org/solrsearch/select"
            params = {
                'q': f'g:"{group_id}" AND a:"{artifact_id}"',
                'rows': 1000,  # Should be enough for most artifacts
                'wt': 'json',
                'fl': 'v,timestamp',
                'sort': 'timestamp desc'  # Newest first
            }
            
            response = self.session.get(search_url, params=params)
            response.raise_for_status()
            data = response.json()
            
            versions = []
            for doc in data['response']['docs']:
                version = doc.get('v', '')
                if version:
                    versions.append(version)
            
            return versions
            
        except Exception as e:
            print(f"[ERROR] Failed to get Maven versions: {e}")
            return []

    def _get_latest_maven_version(self, group_id, artifact_id):
        """Get the latest version for a Maven artifact"""
        try:
            search_url = "https://search.maven.org/solrsearch/select"
            params = {
                'q': f'g:"{group_id}" AND a:"{artifact_id}"',
                'rows': 1,
                'wt': 'json',
                'fl': 'latestVersion'
            }
            
            response = self.session.get(search_url, params=params)
            response.raise_for_status()
            data = response.json()
            
            docs = data['response']['docs']
            if docs:
                return docs[0].get('latestVersion', '')
            
            return None
            
        except Exception as e:
            print(f"[ERROR] Failed to get latest Maven version: {e}")
            return None

    def _scan_maven_artifacts(self, group_id, artifact_id, version, package_info, 
                             only_verified=False, no_verification=False):
        """Download and scan different Maven artifact types"""
        # Convert group_id to path format
        group_path = group_id.replace('.', '/')
        base_url = f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/{version}"
        
        # Artifact types to try (in order of preference for secret scanning)
        artifact_types = [
            ('sources.jar', 'Source JAR'),  # Most likely to contain secrets
            ('jar', 'Main JAR'),            # Compiled code but may have resources
            ('pom', 'POM file'),            # May contain credentials/URLs
        ]
        
        scanned_any = False
        
        for artifact_type, description in artifact_types:
            if artifact_type == 'sources.jar':
                filename = f"{artifact_id}-{version}-sources.jar"
            elif artifact_type == 'pom':
                filename = f"{artifact_id}-{version}.pom"
            else:
                filename = f"{artifact_id}-{version}.jar"
            
            download_url = f"{base_url}/{filename}"
            
            print(f"[INFO] Trying to download {description}: {filename}")
            
            # Check if artifact exists
            try:
                head_response = self.session.head(download_url)
                if head_response.status_code != 200:
                    print(f"[WARN] {description} not available (HTTP {head_response.status_code})")
                    continue
            except Exception as e:
                print(f"[WARN] Error checking {description}: {e}")
                continue
            
            # Download and scan this artifact
            package_identifier = f"{group_id.replace('.', '-')}-{artifact_id}-{version}-{artifact_type.replace('.', '-')}"
            
            try:
                self._download_and_scan_maven_artifact(
                    download_url, package_identifier, description, 
                    only_verified, no_verification, package_info, artifact_type
                )
                scanned_any = True
                
            except Exception as e:
                print(f"[ERROR] Failed to scan {description}: {e}")
                continue
        
        if not scanned_any:
            print(f"[ERROR] No artifacts could be downloaded for {group_id}:{artifact_id}:{version}")

    def _download_and_scan_maven_artifact(self, url, package_identifier, description, 
                                         only_verified=False, no_verification=False, 
                                         package_info=None, artifact_type=None):
        """Download and scan a specific Maven artifact"""
        work_dir = None
        try:
            # Create temporary working directory
            work_dir = tempfile.mkdtemp(dir=self.temp_dir, prefix=f"maven_scan_{package_identifier}_")
            work_path = Path(work_dir)

            print(f"[INFO] Downloading {description} from {url}")

            # Download the artifact
            response = self.session.get(url, stream=True)
            response.raise_for_status()

            # Determine filename and handling
            if artifact_type == 'pom':
                filename = f"{package_identifier}.pom"
                extract_path = work_path / "extracted"
                extract_path.mkdir()
                
                # POM files are XML, save directly
                pom_path = extract_path / "pom.xml"
                with open(pom_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
            else:
                # JAR files (including sources.jar)
                filename = f"{package_identifier}.jar"
                archive_path = work_path / filename

                # Save the downloaded file
                with open(archive_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                print(f"[INFO] Extracting {description}")

                # Extract the JAR file (JARs are ZIP files)
                extract_path = work_path / "extracted"
                extract_path.mkdir()

                try:
                    with zipfile.ZipFile(archive_path, 'r') as jar:
                        jar.extractall(extract_path)
                except zipfile.BadZipFile:
                    print(f"[WARN] {description} is not a valid ZIP/JAR file")
                    return

            print(f"[INFO] Running TruffleHog scan on {description}")

            # Build TruffleHog command
            trufflehog_cmd = [
                'trufflehog',
                'filesystem',
                str(extract_path),
                '--no-update',
                '--json'
            ]

            # Add verification flags
            if only_verified:
                trufflehog_cmd.append('--only-verified')
            elif no_verification:
                trufflehog_cmd.append('--no-verification')

            # Run TruffleHog
            result = subprocess.run(trufflehog_cmd, capture_output=True, text=True)

            if result.stdout:
                print(f"[RESULTS] TruffleHog Results for {description}:")
                print(result.stdout)
                
                # Send Discord alert if verified secrets found
                if package_info:
                    self.discord_logger.send_alert(package_info, result.stdout)
            else:
                print(f"[RESULTS] No secrets found in {description}")

            if result.stderr:
                print(f"[WARN] TruffleHog stderr for {description}:")
                print(result.stderr)

        except Exception as e:
            print(f"[ERROR] Error scanning {description} for {package_identifier}: {e}")
        finally:
            # Cleanup
            if work_dir and os.path.exists(work_dir):
                print(f"[INFO] Cleaning up {work_dir}")
                shutil.rmtree(work_dir)

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
  python scan.py --maven com.google.guava:guava

  # Scan specific version
  python scan.py --pypi requests --version 2.28.1
  python scan.py --maven org.apache.commons:commons-lang3 --version 3.12.0

  # Scan from file (works with all ecosystems)
  python scan.py --crates --file crate_names.txt
  python scan.py --pypi --file python_packages.txt
  python scan.py --npm --file npm_packages.txt
  python scan.py --maven --file maven_packages.txt

  # Scan with Discord alerts
  python scan.py --npm lodash --discord-webhook https://discord.com/api/webhooks/...

  # Scan with rate limiting
  python scan.py --pypi --file packages.txt --delay 2.0

Package Ecosystems:
  --pypi      Scan Python packages from PyPI
  --npm       Scan JavaScript packages from npm (supports scoped packages)
  --crates    Scan Rust crates from crates.io
  --maven     Scan Java packages from Maven Central (format: group_id:artifact_id)

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
    ecosystem_group.add_argument('--maven', action='store_true', help='Scan Maven package (format: group_id:artifact_id)')

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
    ecosystem = 'pypi' if args.pypi else 'npm' if args.npm else 'crates' if args.crates else 'maven'

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
            elif args.maven:
                scanner.scan_maven_package(args.package_name, args.version, args.all_versions,
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
