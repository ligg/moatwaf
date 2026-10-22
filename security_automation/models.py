from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
}


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    purl: str


@dataclass(frozen=True)
class KeVEntry:
    cve_id: str
    date_added: str = ""
    due_date: str = ""
    required_action: str = ""
    ransomware_use: str = ""


@dataclass(frozen=True)
class Finding:
    id: str
    aliases: tuple[str, ...]
    summary: str
    component: str
    version: str
    purl: str
    severity: str = "unknown"
    cvss_score: float | None = None
    fixed_versions: tuple[str, ...] = field(default_factory=tuple)
    kev: bool = False
    kev_due_date: str | None = None
    references: tuple[str, ...] = field(default_factory=tuple)
    cwe_ids: tuple[str, ...] = field(default_factory=tuple)
    rule_family: str | None = None

    @property
    def cve_ids(self) -> tuple[str, ...]:
        identifiers = {self.id, *self.aliases}
        return tuple(sorted(item for item in identifiers if item.startswith("CVE-")))

    @property
    def risk_sort_key(self) -> tuple[int, int, str, str]:
        return (
            0 if self.kev else 1,
            SEVERITY_ORDER.get(self.severity, SEVERITY_ORDER["unknown"]),
            self.id,
            self.purl,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "aliases": list(self.aliases),
            "cveIds": list(self.cve_ids),
            "summary": self.summary,
            "component": self.component,
            "version": self.version,
            "purl": self.purl,
            "severity": self.severity,
            "cvssScore": self.cvss_score,
            "fixedVersions": list(self.fixed_versions),
            "kev": self.kev,
            "kevDueDate": self.kev_due_date,
            "references": list(self.references),
            "cweIds": list(self.cwe_ids),
            "ruleFamily": self.rule_family,
        }

