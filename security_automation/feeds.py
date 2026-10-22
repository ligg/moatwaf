from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from security_automation.models import KeVEntry


USER_AGENT = "MoatWAF-SecurityAutomation/1.0"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_DETAIL_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

Opener = Callable[..., Any]


def fetch_json(
    url: str,
    *,
    opener: Opener | None = None,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    retries: int = 3,
) -> Any:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    body = None
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=request_headers, method=method)
    open_request = opener or urlopen

    for attempt in range(retries):
        try:
            with open_request(request, timeout=timeout) as response:
                return json.load(response)
        except HTTPError as exc:
            retryable = exc.code == 429 or exc.code >= 500
            if not retryable or attempt == retries - 1:
                raise
            time.sleep(2**attempt)
    raise RuntimeError(f"request failed after {retries} attempts: {url}")


def fetch_kev(opener: Opener | None = None) -> dict[str, KeVEntry]:
    document = fetch_json(KEV_URL, opener=opener)
    entries: dict[str, KeVEntry] = {}
    for raw in document.get("vulnerabilities", []):
        cve_id = raw.get("cveID")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            continue
        entries[cve_id] = KeVEntry(
            cve_id=cve_id,
            date_added=str(raw.get("dateAdded") or ""),
            due_date=str(raw.get("dueDate") or ""),
            required_action=str(raw.get("requiredAction") or ""),
            ransomware_use=str(raw.get("knownRansomwareCampaignUse") or ""),
        )
    return entries


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def query_osv(
    purls: Iterable[str],
    *,
    opener: Opener | None = None,
) -> dict[str, list[str]]:
    unique_purls = list(dict.fromkeys(purl for purl in purls if purl))
    matches: dict[str, list[str]] = {purl: [] for purl in unique_purls}
    for purl_chunk in _chunks(unique_purls, 1000):
        payload = {"queries": [{"package": {"purl": purl}} for purl in purl_chunk]}
        document = fetch_json(
            OSV_BATCH_URL,
            opener=opener,
            method="POST",
            payload=payload,
        )
        results = document.get("results", [])
        if len(results) != len(purl_chunk):
            raise ValueError("OSV batch response count does not match query count")
        for purl, result in zip(purl_chunk, results, strict=True):
            vulns = result.get("vulns", []) if isinstance(result, dict) else []
            matches[purl] = sorted(
                {
                    vuln["id"]
                    for vuln in vulns
                    if isinstance(vuln, dict) and isinstance(vuln.get("id"), str)
                }
            )
    return matches


def fetch_osv_vulnerability(
    vuln_id: str,
    *,
    opener: Opener | None = None,
) -> dict[str, Any]:
    document = fetch_json(
        OSV_DETAIL_URL.format(vuln_id=vuln_id),
        opener=opener,
    )
    if not isinstance(document, dict):
        raise ValueError(f"invalid OSV detail for {vuln_id}")
    return document


def fetch_osv_vulnerabilities(
    vuln_ids: Iterable[str],
    *,
    opener: Opener | None = None,
    max_details: int = 250,
    workers: int = 8,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    unique_ids = sorted(set(vuln_ids))
    selected_ids = unique_ids[:max_details]
    errors: list[str] = []
    details: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {
            executor.submit(fetch_osv_vulnerability, vuln_id, opener=opener): vuln_id
            for vuln_id in selected_ids
        }
        for future in as_completed(futures):
            vuln_id = futures[future]
            try:
                details[vuln_id] = future.result()
            except Exception as exc:  # noqa: BLE001 - report feed failures
                errors.append(f"OSV detail {vuln_id}: {exc}")
    return details, errors


def fetch_nvd_cve(
    cve_id: str,
    *,
    api_key: str,
    opener: Opener | None = None,
) -> dict[str, Any] | None:
    headers = {"apiKey": api_key}
    document = fetch_json(
        NVD_CVE_URL.format(cve_id=cve_id),
        opener=opener,
        headers=headers,
    )
    vulnerabilities = document.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    raw = vulnerabilities[0].get("cve", {})
    return raw if isinstance(raw, dict) else None

