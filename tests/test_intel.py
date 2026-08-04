"""Phase 6 tests: local NVD mirror, ATT&CK mapping, detection-aware risk
scoring, enrichment grounding, attack-path correlation, numeric verifier."""

from safeguard.intel.attack import AttackMap
from safeguard.intel.correlate import AttackPathCorrelator
from safeguard.intel.enrich import Enricher
from safeguard.intel.nvd import CVERecord, LocalNVDMirror
from safeguard.intel.risk import RiskScorer
from safeguard.llm.verifier import NumericClaimVerifier
from safeguard.tools.schema import Finding, Severity


def _mirror():
    return LocalNVDMirror({
        "CVE-2020-1938": CVERecord("CVE-2020-1938", cvss=9.8, epss=0.97,
                                   description="Ghostcat"),
    })


# -- NVD mirror ----------------------------------------------------------
def test_nvd_lookup_offline():
    m = _mirror()
    assert m.contains("cve-2020-1938")  # case-insensitive
    rec = m.lookup("CVE-2020-1938")
    assert rec.cvss == 9.8 and "Ghostcat" in rec.description
    assert m.lookup("CVE-9999-0000") is None


def test_nvd_from_sample_file():
    m = LocalNVDMirror.from_file("config/intel/nvd.sample.json")
    assert m.contains("CVE-2021-44228") and m.lookup("CVE-2021-44228").cvss == 10.0


# -- ATT&CK mapping ------------------------------------------------------
def test_attack_map_matches_keywords():
    amap = AttackMap()
    f = Finding(title="Exposed Tomcat Manager", asset_ref="h", source_tool="nuclei",
                severity=Severity.HIGH)
    techs = {t.technique_id for t in amap.map_finding(f)}
    assert "T1190" in techs
    f2 = Finding(title="Reflected XSS on /search", asset_ref="h",
                 source_tool="dalfox")
    assert "T1189" in {t.technique_id for t in amap.map_finding(f2)}


# -- risk scoring (detection-aware) --------------------------------------
def test_undetected_medium_can_outrank_detected_high():
    s = RiskScorer()
    detected_high = s.score(cvss=7.5, epss=0.1, severity=Severity.HIGH,
                            detection_status="DETECTED")
    missed_medium = s.score(cvss=5.5, epss=0.6, severity=Severity.MEDIUM,
                            detection_status="MISSED")
    assert missed_medium.score > detected_high.score


def test_blocked_lowers_risk():
    s = RiskScorer()
    missed = s.score(cvss=8.0, detection_status="MISSED")
    blocked = s.score(cvss=8.0, detection_status="BLOCKED")
    assert blocked.score < missed.score


# -- enrichment grounding ------------------------------------------------
def test_enricher_grounds_cvss_from_mirror():
    enr = Enricher(nvd=_mirror(), attack=AttackMap(), scorer=RiskScorer())
    f = Finding(title="Exposed Tomcat Manager", asset_ref="https://h:8080/manager",
                source_tool="nuclei", severity=Severity.HIGH,
                cve_ids=["CVE-2020-1938"])
    res = enr.enrich([f])
    assert res.cve_hits == 1
    assert f.cvss == 9.8 and f.epss == 0.97           # grounded from mirror
    assert "T1190" in f.attack_techniques
    assert "CVE-2020-1938" in res.grounded_tokens and "9.8" in res.grounded_tokens
    assert f.raw["risk"]["score"] > 0


def test_enricher_flags_cve_not_in_mirror():
    enr = Enricher(nvd=_mirror(), attack=AttackMap(), scorer=RiskScorer())
    f = Finding(title="x", asset_ref="h", source_tool="nuclei",
                cve_ids=["CVE-1999-9999"])
    res = enr.enrich([f])
    assert res.cve_hits == 0 and "CVE-1999-9999" in res.cve_misses


# -- attack-path correlation --------------------------------------------
def test_correlator_orders_by_tactic():
    enr = Enricher(nvd=_mirror(), attack=AttackMap(), scorer=RiskScorer())
    discovery = Finding(title="Open port 8080 service", asset_ref="10.0.0.5",
                        source_tool="nmap", severity=Severity.INFO)
    access = Finding(title="Exposed Tomcat Manager", asset_ref="10.0.0.5",
                     source_tool="nuclei", severity=Severity.HIGH,
                     cve_ids=["CVE-2020-1938"])
    enr.enrich([discovery, access])
    amap = AttackMap()
    paths = AttackPathCorrelator(amap).build([discovery, access])
    assert len(paths) == 1
    tactics = [s.tactic for s in paths[0].steps]
    # steps are ordered along the ATT&CK tactic sequence
    ranks = [amap.tactic_rank(t or "") for t in tactics]
    assert ranks == sorted(ranks)
    assert paths[0].overall_risk > 0


# -- numeric verifier ----------------------------------------------------
def test_numeric_verifier_flags_ungrounded_cve():
    v = NumericClaimVerifier()
    grounded = {"CVE-2020-1938"}
    ok = v.verify("Confirmed CVE-2020-1938 on the host.", grounded)
    assert ok.ok
    bad = v.verify("Also found CVE-2021-00000 (hallucinated).", grounded)
    assert not bad.ok and "CVE-2021-00000" in bad.ungrounded
