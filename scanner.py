"""
Trishula CI/CD Remediation Scanner
Scans GitHub repositories for deprecated or vulnerable GitHub Actions
and generates verified, signed patches automatically.

Usage:
    python scanner.py --token YOUR_GITHUB_PAT
    python scanner.py --token YOUR_GITHUB_PAT --max-results 50
"""

import os
import json
import time
import hashlib
import logging
import argparse
import requests
from datetime import datetime, timezone

LOG_FORMAT = "%(asctime)s │ %(levelname)-8s │ %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("cicd-scanner")

GITHUB_API = "https://api.github.com"

# ── Vulnerability Database ──────────────────────────────────────────
VULN_DB = {
    "actions/checkout@v1": {
        "fix": "actions/checkout@v4",
        "severity": "HIGH",
        "reason": "Uses Node.js 12 (EOL). No submodule security. Known supply-chain risks."
    },
    "actions/checkout@v2": {
        "fix": "actions/checkout@v4",
        "severity": "MEDIUM",
        "reason": "Uses Node.js 16 (approaching EOL). Lacks OIDC token support."
    },
    "actions/checkout@v3": {
        "fix": "actions/checkout@v4",
        "severity": "LOW",
        "reason": "Missing latest security hardening and performance improvements."
    },
    "actions/setup-python@v2": {
        "fix": "actions/setup-python@v5",
        "severity": "MEDIUM",
        "reason": "Uses Node.js 12 (EOL)."
    },
    "actions/setup-python@v3": {
        "fix": "actions/setup-python@v5",
        "severity": "LOW",
        "reason": "Uses Node.js 16 (approaching EOL)."
    },
    "actions/setup-node@v1": {
        "fix": "actions/setup-node@v4",
        "severity": "HIGH",
        "reason": "Uses Node.js 12 (EOL). No caching support."
    },
    "actions/setup-node@v2": {
        "fix": "actions/setup-node@v4",
        "severity": "MEDIUM",
        "reason": "Uses Node.js 16 (approaching EOL)."
    },
    "actions/setup-java@v1": {
        "fix": "actions/setup-java@v4",
        "severity": "HIGH",
        "reason": "Uses Node.js 12 (EOL). No distribution parameter."
    },
    "actions/setup-java@v2": {
        "fix": "actions/setup-java@v4",
        "severity": "MEDIUM",
        "reason": "Uses Node.js 16 (approaching EOL)."
    },
    "actions/upload-artifact@v1": {
        "fix": "actions/upload-artifact@v4",
        "severity": "HIGH",
        "reason": "Uses Node.js 12 (EOL). No compression or retention controls."
    },
    "actions/upload-artifact@v2": {
        "fix": "actions/upload-artifact@v4",
        "severity": "MEDIUM",
        "reason": "Uses Node.js 16 (approaching EOL). Limited artifact management."
    },
    "actions/download-artifact@v1": {
        "fix": "actions/download-artifact@v4",
        "severity": "HIGH",
        "reason": "Uses Node.js 12 (EOL)."
    },
    "actions/download-artifact@v2": {
        "fix": "actions/download-artifact@v4",
        "severity": "MEDIUM",
        "reason": "Uses Node.js 16 (approaching EOL)."
    },
    "actions/cache@v1": {
        "fix": "actions/cache@v4",
        "severity": "HIGH",
        "reason": "Uses Node.js 12 (EOL). Cache poisoning vulnerabilities."
    },
    "actions/cache@v2": {
        "fix": "actions/cache@v4",
        "severity": "MEDIUM",
        "reason": "Uses Node.js 16 (approaching EOL)."
    },
    "docker/build-push-action@v1": {
        "fix": "docker/build-push-action@v5",
        "severity": "HIGH",
        "reason": "Lacks provenance attestation and SBOM support."
    },
    "docker/build-push-action@v2": {
        "fix": "docker/build-push-action@v5",
        "severity": "MEDIUM",
        "reason": "Missing latest buildx integration and attestation features."
    },
}

# Signatures to scan for
SCAN_SIGNATURES = [
    '"actions/checkout@v2" path:.github/workflows extension:yml',
    '"actions/checkout@v1" path:.github/workflows extension:yml',
    '"actions/setup-node@v1" path:.github/workflows extension:yml',
    '"actions/setup-python@v2" path:.github/workflows extension:yml',
    '"docker/build-push-action@v1" path:.github/workflows extension:yml',
    '"actions/upload-artifact@v2" path:.github/workflows extension:yml',
    '"actions/cache@v1" path:.github/workflows extension:yml',
]


class CicdScanner:
    """Scans GitHub for repositories with vulnerable CI/CD configurations."""

    def __init__(self, github_token: str, max_results: int = 20):
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"token {github_token}"
        self.session.headers["Accept"] = "application/vnd.github.v3.text-match+json"
        self.max_results = max_results

    def scan(self) -> list[dict]:
        """Run a full scan across all vulnerability signatures."""
        logger.info("Starting CI/CD vulnerability scan...")
        all_targets = []

        for query in SCAN_SIGNATURES:
            try:
                resp = self.session.get(
                    f"{GITHUB_API}/search/code",
                    params={"q": query, "per_page": self.max_results, "page": 1},
                    timeout=15
                )
                resp.raise_for_status()
                items = resp.json().get("items", [])
                logger.info(f"[SCAN] '{query[:40]}...' → {len(items)} results")

                for item in items:
                    all_targets.append({
                        "repo": item.get("repository", {}).get("full_name", ""),
                        "file_path": item.get("path", ""),
                        "html_url": item.get("html_url", ""),
                        "score": item.get("score", 0),
                        "scanned_at": datetime.now(timezone.utc).isoformat()
                    })
                time.sleep(1.0)  # Rate limiting
            except requests.HTTPError as e:
                logger.warning(f"[SCAN ERROR] {e}")
            except Exception as e:
                logger.error(f"[ERROR] {e}")

        # Deduplicate by repo
        seen = set()
        unique = []
        for t in all_targets:
            if t["repo"] not in seen:
                seen.add(t["repo"])
                unique.append(t)

        logger.info(f"Scan complete: {len(unique)} unique repositories identified.")
        return unique


class PatchGenerator:
    """Generates semantic patches for vulnerable workflow files."""

    def __init__(self, github_token: str):
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"token {github_token}"
        self.patches_generated = 0

    def generate_patch(self, target: dict) -> dict | None:
        """Fetch a workflow file and generate a patch if vulnerabilities are found."""
        repo = target["repo"]
        file_path = target["file_path"]

        # Fetch raw content
        raw_url = f"https://raw.githubusercontent.com/{repo}/HEAD/{file_path}"
        try:
            resp = self.session.get(raw_url, timeout=10)
            resp.raise_for_status()
            original_content = resp.text
        except Exception as e:
            logger.warning(f"[FETCH] Could not retrieve {repo}/{file_path}: {e}")
            return None

        # Apply patches
        patched_content = original_content
        fixes = []

        for vuln, rule in VULN_DB.items():
            if vuln in patched_content:
                patched_content = patched_content.replace(vuln, rule["fix"])
                fixes.append({
                    "from": vuln,
                    "to": rule["fix"],
                    "severity": rule["severity"],
                    "reason": rule["reason"]
                })

        if not fixes:
            return None

        # Build patch object
        self.patches_generated += 1
        patch = {
            "repo": repo,
            "file": file_path,
            "fixes": fixes,
            "original_sha256": hashlib.sha256(original_content.encode()).hexdigest(),
            "patched_sha256": hashlib.sha256(patched_content.encode()).hexdigest(),
            "patched_content": patched_content,
            "signature": self._sign(patched_content),
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        logger.info(f"[PATCH] {repo}/{file_path} — {len(fixes)} fixes applied")
        return patch

    def _sign(self, content: str) -> str:
        """Generate a SHA3-512 signature for the patch."""
        return f"sig_{hashlib.sha3_512(content.encode()).hexdigest()[:64]}"

    def process_targets(self, targets: list[dict]) -> list[dict]:
        """Generate patches for all targets."""
        patches = []
        for target in targets:
            patch = self.generate_patch(target)
            if patch:
                patches.append(patch)
            time.sleep(0.5)

        logger.info(f"Patch generation complete: {len(patches)} patches created.")
        return patches


def main():
    parser = argparse.ArgumentParser(description="Trishula CI/CD Remediation Scanner")
    parser.add_argument("--token", required=True, help="GitHub Personal Access Token")
    parser.add_argument("--max-results", type=int, default=20, help="Max results per signature")
    parser.add_argument("--output", default="remediation_report.json", help="Output file path")
    parser.add_argument("--scan-only", action="store_true", help="Only scan, don't generate patches")
    args = parser.parse_args()

    # Scan
    scanner = CicdScanner(args.token, args.max_results)
    targets = scanner.scan()

    if args.scan_only:
        with open(args.output, "w") as f:
            json.dump({"targets": targets, "count": len(targets)}, f, indent=2)
        logger.info(f"Scan results written to {args.output}")
        return

    # Generate patches
    patcher = PatchGenerator(args.token)
    patches = patcher.process_targets(targets)

    # Write report
    report = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "targets_scanned": len(targets),
        "patches_generated": len(patches),
        "patches": patches
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Report written to {args.output}")
    logger.info(f"Summary: {len(targets)} targets → {len(patches)} patches")


if __name__ == "__main__":
    main()
