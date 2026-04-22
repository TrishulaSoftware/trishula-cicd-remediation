# Trishula CI/CD Remediation Scanner

Automated vulnerability scanning and patch generation for GitHub Actions workflows.

## What It Does

Scans your GitHub repositories for **deprecated, insecure, or EOL GitHub Actions** and generates verified, signed patches that upgrade them to current secure versions.

### Vulnerabilities Detected

| Deprecated Action | Upgraded To | Severity | Why |
|:--|:--|:--|:--|
| `actions/checkout@v1` | `@v4` | HIGH | Node.js 12 EOL, no submodule security |
| `actions/checkout@v2` | `@v4` | MEDIUM | Node.js 16 approaching EOL |
| `actions/setup-node@v1` | `@v4` | HIGH | Node.js 12 EOL, no caching |
| `actions/setup-python@v2` | `@v5` | MEDIUM | Node.js 12 EOL |
| `actions/upload-artifact@v1` | `@v4` | HIGH | Node.js 12 EOL, no compression |
| `actions/cache@v1` | `@v4` | HIGH | Node.js 12 EOL, cache poisoning risks |
| `docker/build-push-action@v1` | `@v5` | HIGH | No provenance attestation or SBOM |
| ...and 10 more | | | |

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Scan and generate patches
python scanner.py --token YOUR_GITHUB_PAT

# Scan only (no patches)
python scanner.py --token YOUR_GITHUB_PAT --scan-only

# Custom output
python scanner.py --token YOUR_GITHUB_PAT --output results.json --max-results 50
```

## Docker

```bash
docker build -t trishula-cicd-scanner .
docker run -e GITHUB_TOKEN=your_pat trishula-cicd-scanner
```

## Output

The scanner produces a JSON report containing:

```json
{
  "scan_timestamp": "2026-04-22T04:00:00Z",
  "targets_scanned": 94,
  "patches_generated": 61,
  "patches": [
    {
      "repo": "org/repo",
      "file": ".github/workflows/ci.yml",
      "fixes": [
        {
          "from": "actions/checkout@v2",
          "to": "actions/checkout@v4",
          "severity": "MEDIUM",
          "reason": "Uses Node.js 16 (approaching EOL)"
        }
      ],
      "original_sha256": "abc123...",
      "patched_sha256": "def456...",
      "signature": "sig_789..."
    }
  ]
}
```

Each patch includes:
- SHA-256 hashes of the original and patched files
- A SHA3-512 cryptographic signature for verification
- The full patched file content ready for a pull request

## License

MIT
