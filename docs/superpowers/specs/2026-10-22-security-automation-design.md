# Security Automation Control Plane Design

## Goal

Create a repository-native control plane that keeps Moat WAF current without adding
runtime dependencies to the WAF container.

The first release automates:

- Scheduled collection of authoritative vulnerability intelligence.
- SBOM-based matching against open-source package vulnerabilities.
- CISA KEV prioritization and optional NVD enrichment.
- A rolling GitHub issue and downloadable scan artifacts.
- Dependabot updates for Docker and GitHub Actions dependencies.
- Signed, deterministic rule-pack builds.

## Non-Goals

- The WAF process will not call external services while serving requests.
- The first release will not automatically publish untested WAF signatures.
- The first release will not manage a long-lived vulnerability database; JSON scan
  artifacts and the rolling issue are the durable state.

## Architecture

```text
GitHub schedule
      |
      v
build image -> CycloneDX SBOM
      |              |
      |              v
      |        OSV batch query
      |              |
      v              v
CISA KEV ------> matcher ------> JSON + Markdown reports
      |              |
      |              v
      |        rolling GitHub issue
      v
optional NVD enrichment

Git tag -> deterministic rule pack -> Sigstore signature -> GitHub release
```

All external network access occurs in GitHub Actions or local maintenance tools.
The WAF container remains a single image with bundled rules.

## Components

### SBOM parsing

`security_automation/sbom.py` reads CycloneDX JSON and returns deduplicated
components containing name, version, and package URL. Components without a package
URL are ignored because they cannot be queried reliably.

### Intelligence feeds

`security_automation/feeds.py` provides:

- CISA KEV catalog retrieval.
- OSV batch matching and vulnerability-detail retrieval.
- Optional NVD CVE enrichment.

Network calls accept an injectable opener so tests remain deterministic and offline.

### Finding normalization

`security_automation/matcher.py` converts OSV results and KEV metadata into
`Finding` records. Findings retain CVE aliases, CVSS/severity, fixed versions,
references, CWE identifiers, and a derived WAF rule family.

Risk ordering is deterministic:

1. Known exploited vulnerabilities.
2. Critical severity.
3. High severity.
4. Medium severity.
5. Low/unknown severity.

### Reporting

`security_automation/report.py` produces:

- `vulnerabilities.json`: machine-readable scan state.
- `report.md`: detailed artifact for operators.
- `issue.md`: concise rolling-issue update.

### Rule packs

`scripts/build_rule_pack.py` builds a deterministic archive containing all built-in
rule YAML files plus a manifest with SHA-256 digests. GitHub Actions signs the
archive with Sigstore keyless signing on version tags.

### Automation policies

- Dependency updates may auto-merge only for patch/minor updates after required
  checks pass.
- Major updates require human approval.
- Rule packs are published only from version tags.
- Scheduled vulnerability scans report findings but do not silently modify rules.

## Configuration

No required repository secrets.

Optional:

- `NVD_API_KEY`: enables NVD enrichment without aggressive rate limiting.

## Success Criteria

- Python automation tests pass offline.
- Existing Lua regression tests continue to pass in the OpenResty container.
- A local CycloneDX fixture produces deterministic JSON and Markdown reports.
- The rule-pack builder produces identical archives for identical inputs.
- Workflow YAML parses successfully.
- Documentation explains manual execution, secrets, rollout, and rollback.

