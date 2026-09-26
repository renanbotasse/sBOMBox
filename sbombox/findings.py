from __future__ import annotations

from typing import Any, Optional

from sbombox.models import Finding
from sbombox.util import (
    cvss_to_severity,
    extract_cvss_score,
    is_malware,
    max_severity,
    normalize_name,
    parse_severity,
    truncate,
)
from sbombox.versioning import better_fixed_in, pick_fixed_version, version_key


def osv_to_finding(raw: dict[str, Any]) -> Optional[Finding]:
    if raw.get("withdrawn"):
        return None
    vuln_id = raw.get("id") or ""
    if not vuln_id:
        return None
    aliases = [a for a in (raw.get("aliases") or []) if a]
    summary = raw.get("summary") or raw.get("details") or ""
    summary = truncate(summary, 280) if isinstance(summary, str) else ""

    db = raw.get("database_specific")
    severity = parse_severity(db.get("severity") if isinstance(db, dict) else None)
    if severity == "UNKNOWN":
        severity = parse_severity(raw.get("severity"))

    cvss = extract_cvss_score(raw.get("severity"))
    if severity == "UNKNOWN" and cvss is not None:
        severity = cvss_to_severity(cvss)
    if is_malware(vuln_id, *aliases):
        severity = "CRITICAL"

    refs = [
        ref["url"]
        for ref in raw.get("references") or []
        if isinstance(ref, dict) and ref.get("url")
    ]

    return Finding(
        vuln_id=vuln_id,
        package=raw.get("_package") or "",
        version=raw.get("_version") or "",
        severity=severity,
        summary=summary,
        fixed_in=extract_fixed_version_osv(
            raw, raw.get("_package") or "", raw.get("_version") or ""
        ),
        aliases=aliases,
        sources=["osv"],
        references=refs[:5],
        cvss=cvss,
    )


def extract_fixed_version_osv(raw: dict[str, Any], package: str, current: str = "") -> Optional[str]:
    """Pick a fixed version suitable for *current*, not the oldest branch fix."""
    pkg_norm = normalize_name(package) if package else ""
    candidates: list[str] = []
    for affected in raw.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        name = normalize_name(pkg.get("name") or "")
        eco = pkg.get("ecosystem") or ""
        if eco and eco != "PyPI":
            continue
        if pkg_norm and name and name != pkg_norm:
            continue
        for r in affected.get("ranges") or []:
            if not isinstance(r, dict):
                continue
            for event in r.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    candidates.append(str(event["fixed"]))
    if not current:
        return min(candidates, key=version_key) if candidates else None
    return pick_fixed_version(current, candidates)


def github_to_finding(raw: dict[str, Any]) -> Optional[Finding]:
    if raw.get("withdrawn_at"):
        return None
    vuln_id = raw.get("ghsa_id") or raw.get("cve_id") or ""
    if not vuln_id:
        return None

    aliases = []
    for key in ("cve_id", "ghsa_id"):
        val = raw.get(key)
        if val and val != vuln_id:
            aliases.append(val)

    severity = parse_severity(raw.get("severity"))
    if is_malware(vuln_id):
        severity = "CRITICAL"

    current = raw.get("_version") or ""
    patched = [
        str(vp["first_patched_version"])
        for vp in raw.get("vulnerabilities") or []
        if isinstance(vp, dict) and vp.get("first_patched_version")
    ]
    fixed_in = pick_fixed_version(current, patched) if current else (patched[0] if patched else None)

    refs = [raw["html_url"]] if raw.get("html_url") else []
    return Finding(
        vuln_id=vuln_id,
        package=raw.get("_package") or "",
        version=current,
        severity=severity,
        summary=raw.get("summary") or "",
        fixed_in=fixed_in,
        aliases=aliases,
        sources=["github"],
        references=refs,
    )


def _merge_finding(target: Finding, other: Finding) -> None:
    ids = target.all_ids() | other.all_ids()
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    ghsas = sorted(i for i in ids if i.startswith("GHSA-"))
    primary = cves[0] if cves else (ghsas[0] if ghsas else target.vuln_id)
    target.vuln_id = primary
    target.aliases = sorted(
        {a for a in (*target.aliases, *other.aliases, *ids) if a.upper() != primary.upper()}
    )
    target.severity = max_severity(target.severity, other.severity)
    target.sources = sorted(set(target.sources + other.sources))
    if not target.summary:
        target.summary = other.summary
    target.fixed_in = better_fixed_in(target.version, target.fixed_in, other.fixed_in)
    for ref in other.references:
        if ref not in target.references:
            target.references.append(ref)
    if other.cvss is not None and (target.cvss is None or other.cvss > target.cvss):
        target.cvss = other.cvss


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings that share CVE / GHSA / PYSEC aliases for the same package@version."""
    groups: list[Finding] = []
    for f in findings:
        merged = False
        for g in groups:
            same_pkg = (
                normalize_name(f.package) == normalize_name(g.package) and f.version == g.version
            )
            if same_pkg and (f.all_ids() & g.all_ids()):
                _merge_finding(g, f)
                merged = True
                break
        if not merged:
            groups.append(f)
    return groups
