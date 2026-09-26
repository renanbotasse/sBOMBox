"""findings.py: OSV/GitHub -> Finding normalization + dedupe merging."""

from __future__ import annotations

from sbombox.findings import (
    _merge_finding,
    dedupe_findings,
    extract_fixed_version_osv,
    github_to_finding,
    osv_to_finding,
)
from sbombox.models import Finding


def _osv_raw(**overrides):
    raw = {
        "id": "PYSEC-2024-1",
        "summary": "Some flaw",
        "aliases": ["CVE-2020-0001"],
        "references": [{"url": "https://example.com/1"}, {"url": "https://example.com/2"}],
        "_package": "pyyaml",
        "_version": "5.3",
    }
    raw.update(overrides)
    return raw


class TestOsvToFinding:
    def test_basic(self):
        f = osv_to_finding(_osv_raw())
        assert f is not None
        assert f.vuln_id == "PYSEC-2024-1"
        assert f.package == "pyyaml"
        assert f.version == "5.3"
        assert f.aliases == ["CVE-2020-0001"]
        assert f.sources == ["osv"]

    def test_withdrawn_returns_none(self):
        assert osv_to_finding(_osv_raw(withdrawn="2024-01-01")) is None

    def test_no_id_returns_none(self):
        assert osv_to_finding(_osv_raw(id="")) is None

    def test_summary_from_details_and_truncation(self):
        f = osv_to_finding(_osv_raw(summary="", details="x" * 500))
        assert len(f.summary) <= 283
        assert f.summary.endswith("...")

    def test_severity_database_specific(self):
        f = osv_to_finding(_osv_raw(database_specific={"severity": "MODERATE"}))
        assert f.severity == "MEDIUM"

    def test_severity_top_level_fallback(self):
        f = osv_to_finding(_osv_raw(severity="CRITICAL"))
        assert f.severity == "CRITICAL"

    def test_severity_numeric_cvss_dict(self):
        f = osv_to_finding(_osv_raw(severity=[{"type": "CVSS_V3", "score": 9.8}]))
        assert f.severity == "CRITICAL"
        assert f.cvss == 9.8

    def test_severity_cvss_vector_string(self):
        # OSV often puts a CVSS:3.x vector in score rather than a label like HIGH.
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        f = osv_to_finding(_osv_raw(severity=[{"type": "CVSS_V3", "score": vector}]))
        assert f is not None
        assert f.cvss == 9.8
        assert f.severity == "CRITICAL"

    def test_malware_forced_critical(self):
        f = osv_to_finding(_osv_raw(id="MAL-2024-1234", aliases=[]))
        assert f.severity == "CRITICAL"


class TestExtractFixedVersionOsv:
    def _affected(self, events):
        return {"affected": [{"package": {"name": "pyyaml", "ecosystem": "PyPI"}, "ranges": [{"events": events}]}]}

    def test_min_when_no_current(self):
        raw = _osv_raw(**self._affected([{"introduced": "0"}, {"fixed": "5.3.1"}, {"fixed": "6.0.0"}]))
        assert extract_fixed_version_osv(raw, "pyyaml") == "5.3.1"

    def test_picks_line_for_current(self):
        raw = _osv_raw(**self._affected([{"fixed": "6.0.0"}, {"fixed": "5.3.1"}, {"fixed": "5.4.0"}]))
        assert extract_fixed_version_osv(raw, "pyyaml", current="5.3.0") == "5.3.1"

    def test_skips_other_ecosystem(self):
        raw = _osv_raw(
            affected=[
                {"package": {"name": "pyyaml", "ecosystem": "npm"}, "ranges": [{"events": [{"fixed": "9.9.9"}]}]},
                {"package": {"name": "pyyaml", "ecosystem": "PyPI"}, "ranges": [{"events": [{"fixed": "5.3.1"}]}]},
            ]
        )
        assert extract_fixed_version_osv(raw, "pyyaml") == "5.3.1"

    def test_no_fixed_versions(self):
        assert extract_fixed_version_osv(_osv_raw(affected=[]), "pyyaml") is None

    def test_never_downgrade(self):
        raw = _osv_raw(**self._affected([{"fixed": "5.2.0"}, {"fixed": "5.3.0"}]))
        assert extract_fixed_version_osv(raw, "pyyaml", current="5.3.0") is None


class TestGithubToFinding:
    def test_basic(self):
        raw = {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cve_id": "CVE-2020-0001",
            "severity": "HIGH",
            "summary": "sum",
            "html_url": "https://github.com/advisories/GHSA-xxxx",
            "_package": "requests",
            "_version": "2.31.0",
            "vulnerabilities": [{"first_patched_version": "2.31.1"}],
        }
        f = github_to_finding(raw)
        assert f.vuln_id == "GHSA-xxxx-yyyy-zzzz"
        assert "CVE-2020-0001" in f.aliases
        assert f.fixed_in == "2.31.1"
        assert f.references == ["https://github.com/advisories/GHSA-xxxx"]

    def test_withdrawn_returns_none(self):
        assert github_to_finding({"ghsa_id": "GHSA-x", "withdrawn_at": "2024-01-01"}) is None

    def test_no_id_returns_none(self):
        assert github_to_finding({}) is None

    def test_cve_id_as_primary(self):
        f = github_to_finding({"cve_id": "CVE-2020-1", "severity": "LOW", "_package": "a", "_version": "1"})
        assert f.vuln_id == "CVE-2020-1"
        assert f.aliases == []

    def test_patch_versions_filtered(self):
        raw = {
            "ghsa_id": "GHSA-x",
            "severity": "HIGH",
            "_package": "a",
            "_version": "1.0",
            "vulnerabilities": [
                {"first_patched_version": "1.0.1"},
                {"first_patched_version": "1.0.2"},
                {"first_patched_version": None},
            ],
        }
        f = github_to_finding(raw)
        assert f.fixed_in == "1.0.1"


class TestDedupeFindings:
    def test_merges_shared_alias(self):
        a = Finding(vuln_id="GHSA-aaaa-aaaa-aaaa", package="pyyaml", version="5.3", severity="HIGH",
                    aliases=["CVE-2020-0001"], sources=["github"], cvss=7.5)
        b = Finding(vuln_id="PYSEC-2024-1", package="PyYAML", version="5.3", severity="CRITICAL",
                    aliases=["CVE-2020-0001"], sources=["osv"], cvss=9.8)
        out = dedupe_findings([a, b])
        assert len(out) == 1
        merged = out[0]
        assert merged.vuln_id == "CVE-2020-0001"  # CVE preferred as primary
        assert merged.severity == "CRITICAL"  # max wins
        assert merged.cvss == 9.8
        assert merged.sources == ["github", "osv"]

    def test_no_merge_different_versions(self):
        a = Finding(vuln_id="GHSA-a", package="pyyaml", version="5.3", severity="HIGH", aliases=["CVE-2020-1"])
        b = Finding(vuln_id="PYSEC-1", package="PyYAML", version="5.4", severity="HIGH", aliases=["CVE-2020-1"])
        assert len(dedupe_findings([a, b])) == 2

    def test_no_merge_disjoint_ids(self):
        a = Finding(vuln_id="GHSA-a", package="pyyaml", version="5.3", severity="HIGH")
        b = Finding(vuln_id="GHSA-b", package="pyyaml", version="5.3", severity="HIGH")
        assert len(dedupe_findings([a, b])) == 2

    def test_empty(self):
        assert dedupe_findings([]) == []

    def test_merge_keeps_summary_and_foreign_refs(self):
        a = Finding(vuln_id="GHSA-a", package="pyyaml", version="5.3", severity="LOW", summary="",
                    references=["https://a"])
        b = Finding(vuln_id="GHSA-a", package="pyyaml", version="5.3", severity="LOW", summary="real summary",
                    references=["https://b"])
        _merge_finding(a, b)
        assert a.summary == "real summary"
        assert "https://b" in a.references
        assert a.references.count("https://a") == 1