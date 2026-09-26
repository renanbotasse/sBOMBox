"""sources/: OSV batch query, GitHub advisories ok-flag, NVD enrichment."""

from __future__ import annotations


from sbombox.models import Finding, Package
from sbombox.sources.github import query_github
from sbombox.sources.nvd import _nvd_metrics, enrich_nvd
from sbombox.sources.osv import query_osv

from conftest import AlwaysFailClient, FakeClient

PKG = Package("requests", "2.31.0", "requirements.txt")


class TestQueryOsv:
    def test_empty_packages_succeeds(self):
        results, ok = query_osv(FakeClient({}), [])
        assert results == [] and ok is True

    def test_no_hits(self):
        client = FakeClient({"https://api.osv.dev/v1/querybatch": (200, {"results": [{"vulns": []}]})})
        results, ok = query_osv(client, [PKG])
        assert results == [] and ok is True

    def test_hits_fetch_details(self):
        client = FakeClient(
            {
                "https://api.osv.dev/v1/querybatch": (
                    200,
                    {"results": [{"vulns": [{"id": "PYSEC-2024-1"}]}]},
                ),
                "https://api.osv.dev/v1/vulns/": (200, {"id": "PYSEC-2024-1", "summary": "s"}),
            }
        )
        results, ok = query_osv(client, [PKG])
        assert ok is True
        assert len(results) == 1
        assert results[0]["_package"] == "requests"
        assert results[0]["_version"] == "2.31.0"
        assert results[0]["_source"] == "osv"

    def test_non200_batch_fails_closed(self):
        client = FakeClient({"https://api.osv.dev/v1/querybatch": (500, None)})
        results, ok = query_osv(client, [PKG])
        assert results == [] and ok is False

    def test_network_error_fails_closed(self):
        results, ok = query_osv(AlwaysFailClient(), [PKG])
        assert results == [] and ok is False

    def test_batching_100(self):
        pkgs = [Package(f"pkg{i}", "1.0.0") for i in range(105)]
        client = FakeClient(
            {
                "https://api.osv.dev/v1/querybatch": (200, {"results": [{"vulns": []}] * 100}),
            }
        )
        results, ok = query_osv(client, pkgs)
        assert ok is True and results == []
        batch_calls = [u for u, _, _ in client.calls if "querybatch" in u]
        assert len(batch_calls) == 2  # 105 packages -> 2 batches


class TestQueryGithub:
    def test_no_token_skips(self):
        client = FakeClient({})
        results, ok = query_github(client, [PKG], "")
        assert results == [] and ok is False
        assert client.calls == []

    def test_token_but_no_packages(self):
        results, ok = query_github(FakeClient({}), [], "tok")
        assert results == [] and ok is True

    def test_success_marks_ok(self):
        client = FakeClient(
            {
                "https://api.github.com/advisories": (200, [{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "summary": "s"}])
            }
        )
        results, ok = query_github(client, [PKG], "tok")
        assert ok is True
        assert len(results) == 1
        assert results[0]["_package"] == "requests"
        assert results[0]["_version"] == "2.31.0"

    def test_withdrawn_filtered(self):
        client = FakeClient(
            {
                "https://api.github.com/advisories": (
                    200,
                    [
                        {"ghsa_id": "GHSA-aaa", "summary": "keep"},
                        {"ghsa_id": "GHSA-bbb", "summary": "drop", "withdrawn_at": "2024-01-01"},
                    ],
                )
            }
        )
        results, ok = query_github(client, [PKG], "tok")
        assert ok is True
        assert [r["ghsa_id"] for r in results] == ["GHSA-aaa"]

    def test_auth_error_not_ok(self):
        # Regression: the old code reported ok=True whenever the loop ran,
        # even when every request failed. A dead source must NOT satisfy the
        # fail-closed gate.
        client = FakeClient({"https://api.github.com/advisories": (403, {"message": "rate limit"})})
        results, ok = query_github(client, [PKG], "tok")
        assert results == [] and ok is False

    def test_all_fail_not_ok(self):
        client = FakeClient({"https://api.github.com/advisories": (500, None)})
        results, ok = query_github(client, [PKG], "tok")
        assert results == [] and ok is False

    def test_network_error_not_ok(self):
        results, ok = query_github(AlwaysFailClient(), [PKG], "tok")
        assert results == [] and ok is False

    def test_mixed_ok_tracking(self):
        def side_effect(url, **kw):
            if "first" in url:
                return 200, []
            return 503, None

        client = FakeClient({})
        client.request = side_effect  # type: ignore[assignment]
        p1 = Package("first-pkg", "1.0.0")
        p2 = Package("second-pkg", "1.0.0")
        results, ok = query_github(client, [p1, p2], "tok")
        assert results == [] and ok is True  # at least one 200 response


class TestNvd:
    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _cve(self, metrics=None, status="Analyzed", tags=None):
        return {"metrics": metrics or {}, "vulnStatus": status, "cveTags": tags}

    def _v31(self, score, severity=None):
        data = {"baseScore": score}
        if severity is not None:
            data["baseSeverity"] = severity
        return {"cvssMetricV31": [{"cvssData": data}]}

    def _client(self, cve):
        return FakeClient({self.NVD_URL: (200, {"vulnerabilities": [{"cve": cve}]})})

    def test_metrics_v31(self):
        assert _nvd_metrics(self._cve(self._v31(9.8, "CRITICAL"))) == (9.8, "CRITICAL", "Analyzed")

    def test_metrics_v2_fallback(self):
        metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 6.5, "baseSeverity": "MEDIUM"}}]}
        score, sev, _ = _nvd_metrics(self._cve(metrics))
        assert (score, sev) == (6.5, "MEDIUM")

    def test_no_metrics(self):
        assert _nvd_metrics(self._cve()) == (None, None, "Analyzed")

    def test_tag_fallback_status(self):
        cve = {"metrics": {}, "cveTags": [{"tag": "exclusively-hostile"}]}
        assert _nvd_metrics(cve)[2] == "exclusively-hostile"

    def test_enrich_sets_cvss_and_link(self):
        client = self._client(self._cve(self._v31(9.8, "CRITICAL")))
        f = Finding(vuln_id="PYSEC-1", package="a", version="1", severity="UNKNOWN",
                    aliases=["CVE-2020-0001"])
        enrich_nvd(client, [f], None)
        assert f.cvss == 9.8
        assert f.severity == "CRITICAL"
        assert any("cve.org/CVERecord?id=CVE-2020-0001" in r for r in f.references)
        assert f.nvd_status == "Analyzed"

    def test_enrich_rejected_resets_severity(self):
        client = self._client(self._cve(self._v31(9.8, "CRITICAL"), status="Rejected"))
        f = Finding(vuln_id="CVE-2020-0001", package="a", version="1", severity="CRITICAL")
        enrich_nvd(client, [f], None)
        assert f.severity == "UNKNOWN"
        assert (f.nvd_status or "").lower() == "rejected"

    def test_enrich_deferred_keeps_severity(self):
        client = self._client(self._cve(self._v31(7.5, "HIGH"), status="Deferred"))
        f = Finding(vuln_id="CVE-2020-0001", package="a", version="1", severity="UNKNOWN")
        enrich_nvd(client, [f], None)
        assert f.cvss == 7.5
        assert f.severity == "HIGH"
        assert (f.nvd_status or "").lower() == "deferred"

    def test_enrich_deferred_cvss_fallback_without_label(self):
        client = self._client(self._cve(self._v31(9.1), status="Deferred"))
        f = Finding(vuln_id="CVE-2020-0001", package="a", version="1", severity="UNKNOWN")
        enrich_nvd(client, [f], None)
        assert f.cvss == 9.1
        assert f.severity == "CRITICAL"

    def test_enrich_no_cves_skips(self):
        client = FakeClient({})
        f = Finding(vuln_id="GHSA-aaaa-bbbb-cccc", package="a", version="1", severity="HIGH")
        enrich_nvd(client, [f], None)
        assert client.calls == []
        assert f.cvss is None

    def test_enrich_keeps_existing_higher_severity(self):
        client = self._client(self._cve(self._v31(9.8, "CRITICAL")))
        f = Finding(vuln_id="CVE-2020-0001", package="a", version="1", severity="HIGH")
        enrich_nvd(client, [f], None)
        assert f.severity == "HIGH"  # OSV verdict wins; only UNKNOWN is upgraded

    def test_enrich_network_failure_tolerated(self):
        client = AlwaysFailClient()
        f = Finding(vuln_id="CVE-2020-0001", package="a", version="1", severity="HIGH")
        enrich_nvd(client, [f], None)  # must not raise
        assert f.references and any("cve.org" in r for r in f.references)