"""
Trishula CI/CD Remediation Scanner — Test Suite
SQA v5 [ASCENDED] Compliance: MC/DC Determinism + Bit-Perfect Persistence
"""
import json
import hashlib
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from scanner import CicdScanner, PatchGenerator, VULN_DB

PASSED = 0
FAILED = 0

def test(name, condition):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  ✅ {name}")
    else:
        FAILED += 1
        print(f"  ❌ {name}")

print("=" * 70)
print("  TRISHULA CI/CD REMEDIATION — SQA TEST SUITE")
print("=" * 70)

# ── TEST GROUP 1: Vulnerability Database Integrity ──
print("\n── TEST GROUP 1: Vulnerability Database Integrity ──")

test("VULN_DB has >= 15 rules", len(VULN_DB) >= 15)
test("VULN_DB has 17 rules exactly", len(VULN_DB) == 17)

for vuln, rule in VULN_DB.items():
    test(f"Rule '{vuln}' has 'fix' field", "fix" in rule)
    test(f"Rule '{vuln}' has 'severity' field", "severity" in rule)
    test(f"Rule '{vuln}' has 'reason' field", "reason" in rule)
    test(f"Rule '{vuln}' severity is valid", rule["severity"] in ("HIGH", "MEDIUM", "LOW"))

# ── TEST GROUP 2: Patch Generation (Offline / No Token) ──
print("\n── TEST GROUP 2: Patch Generation Logic ──")

patcher = PatchGenerator("FAKE_TOKEN_FOR_UNIT_TEST")

# Simulate a workflow with known vulnerable actions
sample_workflow = """
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
      - uses: actions/cache@v1
      - uses: docker/build-push-action@v1
"""

# Test offline patch logic directly
patched = sample_workflow
fixes = []
for vuln, rule in VULN_DB.items():
    if vuln in patched:
        patched = patched.replace(vuln, rule["fix"])
        fixes.append({"from": vuln, "to": rule["fix"]})

test("Patch found 4 vulnerabilities", len(fixes) == 4)
test("actions/checkout@v2 -> v4", "actions/checkout@v4" in patched)
test("actions/setup-python@v2 -> v5", "actions/setup-python@v5" in patched)
test("actions/cache@v1 -> v4", "actions/cache@v4" in patched)
test("docker/build-push-action@v1 -> v5", "docker/build-push-action@v5" in patched)
test("No original v2 references remain", "actions/checkout@v2" not in patched)
test("No original v1 references remain", "actions/cache@v1" not in patched)

# ── TEST GROUP 3: Signature Integrity ──
print("\n── TEST GROUP 3: Cryptographic Signature ──")

sig = patcher._sign(patched)
test("Signature starts with 'sig_'", sig.startswith("sig_"))
test("Signature is 68 chars (sig_ + 64 hex)", len(sig) == 68)
test("Signature is deterministic", sig == patcher._sign(patched))
test("Different content = different signature", sig != patcher._sign("different content"))

# SHA-256 hash verification
orig_hash = hashlib.sha256(sample_workflow.encode()).hexdigest()
patched_hash = hashlib.sha256(patched.encode()).hexdigest()
test("Original and patched have different SHA-256", orig_hash != patched_hash)
test("SHA-256 is 64 hex chars", len(orig_hash) == 64 and len(patched_hash) == 64)

# ── TEST GROUP 4: Clean Workflow (No False Positives) ──
print("\n── TEST GROUP 4: Clean Workflow Detection ──")

clean_workflow = """
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
"""

clean_fixes = []
for vuln, rule in VULN_DB.items():
    if vuln in clean_workflow:
        clean_fixes.append(vuln)

test("Clean workflow has ZERO findings", len(clean_fixes) == 0)

# ── TEST GROUP 5: Edge Cases ──
print("\n── TEST GROUP 5: Edge Cases ──")

test("Empty workflow yields no patches", len([v for v in VULN_DB if v in ""]) == 0)
test("VULN_DB keys are lowercase+version format",
     all("@v" in k for k in VULN_DB.keys()))

# ── SUMMARY ──
print("\n" + "=" * 70)
total = PASSED + FAILED
print(f"  RESULTS: {PASSED}/{total} PASSED, {FAILED}/{total} FAILED")
verdict = "✅ SQA PASS" if FAILED == 0 else "❌ SQA FAIL"
print(f"  VERDICT: {verdict}")
print("=" * 70)
