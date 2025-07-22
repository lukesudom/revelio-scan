# REVELIO - Package Secret Scanner

A containerized tool that automatically downloads, extracts, and scans packages from **PyPI**, **npm**, and **crates.io** for embedded secrets, API keys, tokens, and other sensitive information using TruffleHog.

## Features

- **Multi-Ecosystem Support**: PyPI, npm, and crates.io  
- **Batch Processing**: Scan hundreds of packages from text files  
- **Discord Integration**: Real-time alerts for verified secrets  
- **Rate Limiting**: Configurable delays for respectful scanning  
- **Version Control**: Scan specific versions or all versions  
- **Verification Options**: Configurable TruffleHog verification modes

## Quick Start

### Build the Container

```bash
# Clone the repository
git clone https://github.com/lukesudom/revelio-scan.git
cd revelio-scan

# Build the Docker image
docker build -t revelio-scan .

# Run with an interactive shell for debugging
docker run -it revelio-scan

# Or run a direct scan
docker run revelio-scan python scan.py --npm lodash
```

## Usage

### Single Package Scans

```bash
# Scan latest version of packages
python scan.py --npm @babel/core
python scan.py --pypi requests  
python scan.py --crates serde

# Scan specific version
python scan.py --pypi requests --version 2.28.1
python scan.py --crates tokio --version 1.25.0

# Scan all versions (use with caution!)
python scan.py --npm lodash --all-versions
```

### Batch Processing from Files

```bash
# Scan packages from text files (one package name per line)
python scan.py --pypi --file python_packages.txt
python scan.py --npm --file npm_packages.txt  
python scan.py --crates --file crates_names.txt

# Batch scan with rate limiting (delay between packages)
python scan.py --crates --file crates_names.txt --delay 2.0

```

### TruffleHog Verification Options

```bash
# Only report verified secrets (fewer false positives)
python scan.py --npm lodash --only-verified

# Skip verification entirely (faster but more false positives)  
python scan.py --pypi requests --no-verification

# Default behavior (standard verification)
python scan.py --crates serde
```

### Discord Integration

```bash
# Get Discord alerts when verified secrets are found
python scan.py --crates --file crates_names.txt \
  --only-verified \
  --discord-webhook https://discord.com/api/webhooks/YOUR_WEBHOOK

# Batch scan with alerts and rate limiting
python scan.py --pypi --file packages.txt \
  --discord-webhook https://discord.com/api/webhooks/YOUR_WEBHOOK \
  --delay 1.5
```

## Advanced Examples

```bash
# Security research on Rust ecosystem
python scan.py --crates --file top_crates.txt --only-verified --discord-webhook URL

# Fast preliminary scan without verification
python scan.py --npm --file suspicious_packages.txt --no-verification --delay 0.5

# Comprehensive scan of specific versions
python scan.py --pypi tensorflow --version 2.12.0 --only-verified

# Scan scoped npm packages from file
echo "@types/node" > scoped_packages.txt
echo "@babel/core" >> scoped_packages.txt
python scan.py --npm --file scoped_packages.txt
```

# This creates crates_names.txt with one package name per line
```
python scan.py --crates --file crates_names.txt --delay 1.0
```

## Command Reference

### Package Ecosystems
* `--pypi`: Scan Python packages from PyPI
* `--npm`: Scan JavaScript packages from npm (supports scoped packages like `@scope/name`)
* `--crates`: Scan Rust crates from crates.io

### Input Options
* `package_name`: Single package name to scan
* `--file FILE`: Text file containing package names (one per line) - **works with all ecosystems**

### Version Options
* `--version VERS`: Scan a specific version
* `--all-versions`: Scan all available versions **Use with caution for packages with many versions**
* *No flag*: Scan the latest version (default)

### TruffleHog Options
* `--only-verified`: Only report secrets that have been verified by TruffleHog
* `--no-verification`: Skip verification entirely (faster execution, more false positives)
* *No flag*: Use TruffleHog's default verification behavior

### Batch Processing Options
* `--delay SECONDS`: Delay between packages when scanning from file (default: 1.0)

### Discord Integration
* `--discord-webhook URL`: Discord webhook URL for alerts when verified secrets are found

### Help

```bash
python scan.py --help
```

## Architecture

Revelio works by:

1. **Fetching** package metadata from the respective registry (PyPI/npm/crates.io)
2. **Downloading** source distributions, tarballs, or .crate files to `/tmp`
3. **Extracting** archives to temporary directories
   - `.tar.gz`, `.tgz` for PyPI and npm
   - `.crate` files (gzipped tarballs) for crates.io
   - `.zip` files when available
4. **Scanning** extracted code with TruffleHog in JSON mode
5. **Reporting** any discovered secrets with detailed output
6. **Alerting** via Discord webhooks for verified secrets (optional)
7. **Cleaning** up all temporary files automatically

## File Formats

### Input Text Files
```
# packages.txt - one package name per line
requests
flask  
django
numpy
pandas
```


## Security Considerations

**Rate Limiting**: Always use appropriate delays when batch scanning to avoid overwhelming package registries

**Verification**: Use `--only-verified` for production security assessments to reduce false positives

**Discord Webhooks**: Keep webhook URLs secure and use dedicated channels for security alerts

## Prerequisites

- Docker or Python 3.8+
- TruffleHog installed and available in PATH
- Internet connection for package downloads
- Optional: Discord webhook for alerts

**Disclaimer**: This tool is for security research and authorized testing only. Always ensure you have permission to scan packages and respect the terms of service of package registries.