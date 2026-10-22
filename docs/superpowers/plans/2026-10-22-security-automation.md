# Security Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Add a repository-native, scheduled security control plane and signed rule-pack release flow without adding runtime dependencies to Moat WAF.

**Architecture:** A Python standard-library package parses CycloneDX SBOMs, queries OSV and CISA KEV, optionally enriches findings with NVD, and emits JSON/Markdown reports. GitHub Actions builds the WAF image, generates an SBOM, runs the matcher, maintains a rolling issue, and publishes signed rule packs on version tags.

**Tech Stack:** Python 3.12 standard library, CycloneDX JSON, OSV API, CISA KEV JSON, NVD API 2.0, GitHub Actions, Trivy, Sigstore cosign.

**Spec:** `docs/superpowers/specs/2026-10-22-security-automation-design.md`

## Global Constraints

- No new WAF runtime dependency.
- Python code must run with Python 3.11 or newer and use only the standard library.
- Network code must be injectable and deterministic in tests.
- Vulnerability scans must generate reports without directly editing production rules.
- Rule-pack builds must be deterministic for identical inputs.
- Existing Lua tests must continue to pass.

---

### Task 1: CycloneDX SBOM parsing

**Files:**
- Create: `security_automation/__init__.py`
- Create: `security_automation/models.py`
- Create: `security_automation/sbom.py`
- Test: `tests/security_automation/test_sbom.py`

**Interfaces:**
- Produces: `Component(name: str, version: str, purl: str)`.
- Produces: `load_components(path: Path) -> list[Component]`.

- [x] **Step 1: Write the failing test**

```python
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from security_automation.sbom import load_components


def test_load_components_deduplicates_purls():
    with TemporaryDirectory() as tmp:
        path = Path(tmp) / "sbom.json"
        path.write_text(json.dumps({
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "django", "version": "3.2.0", "purl": "pkg:pypi/django@3.2.0"},
                {"name": "django", "version": "3.2.0", "purl": "pkg:pypi/django@3.2.0"},
            ],
        }))
        components = load_components(path)
    assert [component.purl for component in components] == ["pkg:pypi/django@3.2.0"]
```

- [x] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.security_automation.test_sbom -v`

Expected: FAIL because `security_automation` does not exist.

- [x] **Step 3: Write minimal implementation**

Implement `Component` as a frozen dataclass and `load_components()` with recursive
CycloneDX component traversal, package-URL validation, and stable deduplication.

- [x] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.security_automation.test_sbom -v`

Expected: PASS.

### Task 2: Feed retrieval and finding normalization

**Files:**
- Create: `security_automation/feeds.py`
- Create: `security_automation/matcher.py`
- Test: `tests/security_automation/test_matcher.py`

**Interfaces:**
- Consumes: `Component`.
- Produces: `fetch_kev(opener=...) -> dict[str, KeVEntry]`.
- Produces: `query_osv(purls, opener=...) -> dict[str, list[str]]`.
- Produces: `fetch_osv_vulnerability(vuln_id, opener=...) -> dict`.
- Produces: `build_findings(components, osv_matches, details_by_id, kev, cwe_to_rule) -> list[Finding]`.

- [x] **Step 1: Write the failing test**

```python
def test_build_findings_marks_kev_and_extracts_fixed_versions():
    component = Component("django", "3.2.0", "pkg:pypi/django@3.2.0")
    details = {
        "GHSA-test": {
            "id": "GHSA-test",
            "aliases": ["CVE-2026-0001"],
            "summary": "Example issue",
            "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-89"]},
            "affected": [{"ranges": [{"events": [{"fixed": "3.2.9"}]}]}],
        }
    }
    kev = {"CVE-2026-0001": KeVEntry("CVE-2026-0001", "2026-10-20", "2026-11-10")}
    findings = build_findings(
        [component],
        {component.purl: ["GHSA-test"]},
        details,
        kev,
        {"CWE-89": "SQLI"},
    )
    assert findings[0].kev is True
    assert findings[0].fixed_versions == ["3.2.9"]
    assert findings[0].rule_family == "SQLI"
```

- [x] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.security_automation.test_matcher -v`

Expected: FAIL because feed and matcher interfaces do not exist.

- [x] **Step 3: Write minimal implementation**

Implement URL requests with `urllib.request`, bounded retries, OSV batch chunks of
1000, KEV indexing by CVE, severity extraction, CWE-to-rule mapping, fixed-version
extraction, and stable risk sorting.

- [x] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.security_automation.test_matcher -v`

Expected: PASS.

### Task 3: Reports and command-line entry point

**Files:**
- Create: `security_automation/report.py`
- Create: `security_automation/cli.py`
- Test: `tests/security_automation/test_report.py`

**Interfaces:**
- Consumes: normalized findings and scan metadata.
- Produces: `render_report(scan) -> str`.
- Produces: `render_issue(scan) -> str`.
- Produces: `python -m security_automation.cli scan --sbom PATH --output-dir PATH`.

- [x] **Step 1: Write the failing test**

```python
def test_render_report_prioritizes_known_exploited_findings():
    scan = {"generatedAt": "2026-10-22T00:00:00Z", "findings": [kev_finding, critical_finding]}
    report = render_report(scan)
    assert report.index("CVE-2026-0001") < report.index("CVE-2026-0002")
    assert "Known exploited" in report
```

- [x] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.security_automation.test_report -v`

Expected: FAIL because report functions do not exist.

- [x] **Step 3: Write minimal implementation**

Generate a summary table, severity counts, KEV count, top findings, rule-family
coverage gaps, and remediation next steps. The rolling issue body must stay concise.

- [x] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.security_automation.test_report -v`

Expected: PASS.

### Task 4: Deterministic rule-pack builder

**Files:**
- Create: `scripts/build_rule_pack.py`
- Test: `tests/security_automation/test_rule_pack.py`

**Interfaces:**
- Produces: `build_rule_pack(rules_dir: Path, output_dir: Path, version: str) -> RulePack`.
- Produces: `<output>/moat-waf-rules-<version>.tar.gz`.
- Produces: `<output>/moat-waf-rules-<version>.tar.gz.sha256`.

- [x] **Step 1: Write the failing test**

```python
def test_rule_pack_is_deterministic():
    first = build_rule_pack(Path("rules"), output_a, "v1.0.0")
    second = build_rule_pack(Path("rules"), output_b, "v1.0.0")
    assert sha256(first.archive) == sha256(second.archive)
```

- [x] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.security_automation.test_rule_pack -v`

Expected: FAIL because the builder does not exist.

- [x] **Step 3: Write minimal implementation**

Sort rule files, create a manifest with file digests, normalize tar metadata, write
gzip with `mtime=0`, and emit a SHA-256 sidecar.

- [x] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.security_automation.test_rule_pack -v`

Expected: PASS.

### Task 5: GitHub automation and documentation

**Files:**
- Create: `.github/workflows/security-intel.yml`
- Create: `.github/workflows/rule-pack-release.yml`
- Create: `.github/workflows/dependabot-auto-merge.yml`
- Create: `.github/dependabot.yml`
- Create: `security/cwe-rule-map.json`
- Create: `security/README.md`
- Modify: `README.md`
- Modify: `.gitignore`

- [x] **Step 1: Add scheduled intelligence workflow**

Build `moat-waf:security-scan`, generate a CycloneDX SBOM with Trivy, run Python
automation tests, run the scanner, upload artifacts, and create/comment on a rolling
`[security-intel] Vulnerability backlog` issue.

- [x] **Step 2: Add rule-pack release workflow**

On `v*` tags, run tests, build the deterministic rule pack, sign it with Sigstore
keyless signing, and attach the archive, checksum, signature, and certificate to the
GitHub release.

- [x] **Step 3: Add dependency automation**

Configure weekly Dependabot updates for Docker and GitHub Actions. Auto-merge only
patch and minor updates after required checks pass.

- [x] **Step 4: Document operation and rollback**

Document manual scan commands, optional `NVD_API_KEY`, issue workflow, rule-pack
verification, artifact retention, and rollback to the previous signed pack.

- [x] **Step 5: Verify workflow syntax**

Run a Ruby YAML parse over `.github/workflows/*.yml` and
`.github/dependabot.yml`.

Expected: every file parses without error.

### Task 6: Full verification

- [x] **Step 1: Run Python tests**

Run: `python3 -m unittest discover -s tests/security_automation -v`

Expected: 0 failures.

- [x] **Step 2: Run existing Lua regression tests**

Run the OpenResty Docker command used by `.github/workflows/docker-publish.yml`.

Expected: all existing Lua unit checks pass.

- [x] **Step 3: Run an offline end-to-end scan**

Use test fixtures to generate `vulnerabilities.json`, `report.md`, and `issue.md`.

Expected: all outputs exist and contain deterministic finding counts.

- [x] **Step 4: Inspect the final diff**

Run: `git diff --check` and `git status --short`.

Expected: no whitespace errors and only intended files changed.

