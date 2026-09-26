"""util helpers: normalization, severity, truncate, write_json."""

from __future__ import annotations

import json

from sbombox.util import (
    cvss_to_severity,
    cvss_vector_base_score,
    extract_cvss_score,
    first_cve,
    is_malware,
    max_severity,
    normalize_name,
    parse_severity,
    severity_rank,
    truncate,
    utc_now_iso,
    write_json,
)


class TestNormalizeName:
    def test_pep503(self):
        assert normalize_name("My_Package.Name") == "my-package-name"
        assert normalize_name("Pillow") == "pillow"
        assert normalize_name("zope.interface") == "zope-interface"


CVSS31_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class TestSeverity:
    def test_rank_order(self):
        assert severity_rank("CRITICAL") > severity_rank("HIGH") > severity_rank("MEDIUM") > severity_rank("LOW") > severity_rank("UNKNOWN")

    def test_rank_unknown_default(self):
        assert severity_rank("") == 0
        assert severity_rank(None) == 0  # type: ignore[arg-type]
        assert severity_rank("garbage") == 0

    def test_max_severity(self):
        assert max_severity("LOW", "HIGH") == "HIGH"
        assert max_severity("HIGH", "HIGH") == "HIGH"
        assert max_severity("UNKNOWN", "MEDIUM") == "MEDIUM"

    def test_parse_strings(self):
        assert parse_severity("moderate") == "MEDIUM"
        assert parse_severity("critical") == "CRITICAL"
        assert parse_severity("nonsense") == "UNKNOWN"
        assert parse_severity(None) == "UNKNOWN"

    def test_parse_numeric_dict_score(self):
        # Regression: numeric CVSS scores in dicts were dropped to UNKNOWN
        assert parse_severity({"score": 9.8}) == "CRITICAL"
        assert parse_severity({"score": 7.5}) == "HIGH"
        assert parse_severity({"score": 4.1}) == "MEDIUM"
        assert parse_severity({"score": 0.5}) == "LOW"
        assert parse_severity({"score": 0}) == "UNKNOWN"

    def test_parse_list_takes_max(self):
        assert parse_severity(["LOW", "CRITICAL"]) == "CRITICAL"
        assert parse_severity([{"score": 9.8}, "LOW"]) == "CRITICAL"
        assert parse_severity([]) == "UNKNOWN"

    def test_parse_cvss_vector_dict(self):
        assert parse_severity({"type": "CVSS_V3", "score": CVSS31_CRITICAL}) == "CRITICAL"

    def test_parse_cvss_vector_string(self):
        assert parse_severity(CVSS31_CRITICAL) == "CRITICAL"

    def test_cvss_vector_known_score(self):
        assert cvss_vector_base_score(CVSS31_CRITICAL) == 9.8
        assert cvss_vector_base_score("not-a-vector") is None
        assert extract_cvss_score([{"type": "CVSS_V3", "score": CVSS31_CRITICAL}]) == 9.8

    def test_cvss_bands(self):
        assert cvss_to_severity(9.0) == "CRITICAL"
        assert cvss_to_severity(8.9) == "HIGH"
        assert cvss_to_severity(7.0) == "HIGH"
        assert cvss_to_severity(4.0) == "MEDIUM"
        assert cvss_to_severity(0.1) == "LOW"
        assert cvss_to_severity(0.0) == "UNKNOWN"


class TestMisc:
    def test_truncate(self):
        assert truncate("short", 80) == "short"
        assert truncate("x" * 100, 10) == "xxxxxxx..."

    def test_first_cve(self):
        assert first_cve(["PYSEC-2024-1", "CVE-2020-1", "GHSA-ab"]) == "CVE-2020-1"
        assert first_cve(["GHSA-ab", "PYSEC-2024-1"]) is None
        assert first_cve([]) is None

    def test_is_malware(self):
        assert is_malware("MAL-2024-1234")
        assert is_malware("CVE-2020-1", "MAL-2024-1")
        assert not is_malware("CVE-2020-1")
        assert not is_malware("", None)  # type: ignore[arg-type]

    def test_utc_now_iso(self):
        s = utc_now_iso()
        assert s.endswith("Z")
        assert "T" in s

    def test_write_json(self, tmp_path):
        p = tmp_path / "out.json"
        write_json(p, {"a": 1})
        assert json.loads(p.read_text()) == {"a": 1}
        assert p.read_text().endswith("\n")