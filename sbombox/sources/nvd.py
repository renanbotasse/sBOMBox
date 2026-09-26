from __future__ import annotations

import time
import urllib.parse
from typing import Any, Optional

from sbombox.http import HttpClient
from sbombox.models import Finding
from sbombox.util import cvss_to_severity, first_cve, log

NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ORG = "https://www.cve.org/CVERecord?id={id}"


def _nvd_metrics(cve: dict[str, Any]) -> tuple[Optional[float], Optional[str], Optional[str]]:
    metrics = cve.get("metrics") or {}
    score = None
    severity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if not arr or not isinstance(arr[0], dict):
            continue
        cvss_data = arr[0].get("cvssData") or {}
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
        break

    tag = None
    for entry in cve.get("cveTags") or []:
        if isinstance(entry, dict) and entry.get("tag"):
            tag = entry["tag"]
            break
    return score, severity, cve.get("vulnStatus") or tag


def _apply_nvd_info(finding: Finding, info: dict[str, Any]) -> None:
    """Apply cached NVD metrics. Rejected → UNKNOWN; Deferred keeps score/severity."""
    score = info.get("score")
    if score is not None:
        try:
            finding.cvss = float(score)
        except (TypeError, ValueError):
            pass

    finding.nvd_status = info.get("status")
    if (finding.nvd_status or "").lower() == "rejected":
        finding.severity = "UNKNOWN"
        return
    if finding.severity != "UNKNOWN":
        return
    if info.get("severity"):
        finding.severity = str(info["severity"]).upper()
    elif finding.cvss is not None:
        finding.severity = cvss_to_severity(finding.cvss)


def enrich_nvd(
    client: HttpClient,
    findings: list[Finding],
    api_key: Optional[str],
) -> None:
    cve_ids = sorted({cve for f in findings if (cve := first_cve(f.all_ids()))})
    if not cve_ids:
        return

    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.7 if api_key else 6.1
    eta_min = len(cve_ids) * delay / 60
    log(
        f"NVD: enriching {len(cve_ids)} CVE(s) "
        f"({'with API key' if api_key else 'no API key, ~6s each'} ≈ {eta_min:.1f} min)..."
    )
    log("      tip: use --no-nvd for a fast local pass (OSV severity is enough for the gate)")
    cache: dict[str, dict[str, Any]] = {}

    for idx, cve_id in enumerate(cve_ids, 1):
        log(f"NVD: {idx}/{len(cve_ids)} {cve_id}")
        url = f"{NVD_CVE}?{urllib.parse.urlencode({'cveId': cve_id})}"
        try:
            status, data = client.request(url, headers=headers or None)
        except RuntimeError as e:
            log(f"NVD lookup failed for {cve_id}: {e}")
            time.sleep(delay)
            continue
        time.sleep(delay)
        if status != 200 or not isinstance(data, dict):
            continue
        vulns = data.get("vulnerabilities") or []
        if not vulns or not isinstance(vulns[0], dict):
            continue
        cve = vulns[0].get("cve") or {}
        score, severity, vuln_status = _nvd_metrics(cve)
        cache[cve_id] = {"score": score, "severity": severity, "status": vuln_status}
    log("NVD: done")

    for finding in findings:
        cve = first_cve(finding.all_ids())
        if not cve:
            continue
        link = CVE_ORG.format(id=cve)
        if link not in finding.references:
            finding.references.append(link)
        if cve in cache:
            _apply_nvd_info(finding, cache[cve])
