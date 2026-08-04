"""Phase 8 tests: ATT&CK heatmap, detection-gap report, grounded narratives,
and the report-bundle writer."""

from safeguard.graph.state import AgentState
from safeguard.reporting.heatmap import AttackHeatmap
from safeguard.reporting.report import Reporter
from safeguard.tools.schema import Finding, Severity


def _state():
    st = AgentState(engagement_id="eng-rep-001", mode="black_box",
                    profile="non_destructive", targets=["10.20.30.44"])
    f = Finding(title="Exposed Tomcat Manager", asset_ref="https://10.20.30.44:8080/manager",
                source_tool="nuclei", severity=Severity.HIGH,
                cve_ids=["CVE-2020-1938"], attack_techniques=["T1190"])
    f.raw["risk"] = {"score": 92.0, "priority": "critical"}
    f.raw["sources"] = ["nuclei"]
    st.ledger.add(f)
    st.grounded_tokens = ["CVE-2020-1938", "9.8"]
    st.detections = [
        {"action_ref": "recon", "target": "10.20.30.44", "technique": "T1046",
         "verdict": "DETECTED", "source": "aggregate", "rule_id": "86601",
         "ttd_seconds": 40.0},
        {"action_ref": "scan", "target": "https://10.20.30.44:8080/manager",
         "technique": "T1595", "verdict": "MISSED", "source": "aggregate",
         "rule_id": None, "ttd_seconds": None},
    ]
    st.detection_status = {"10.20.30.44": "MISSED"}
    st.attack_paths = [{"asset": "10.20.30.44", "overall_risk": 92.0,
                        "steps": [{"technique_id": "T1190", "detection": "MISSED"}]}]
    return st


# -- heatmap -------------------------------------------------------------
def test_heatmap_counts_and_coverage():
    dets = [{"technique": "T1046", "verdict": "DETECTED"},
            {"technique": "T1595", "verdict": "MISSED"},
            {"technique": "T1046", "verdict": "BLOCKED"}]
    hm = AttackHeatmap.from_detections(dets)
    assert hm.cells["T1046"]["DETECTED"] == 1 and hm.cells["T1046"]["BLOCKED"] == 1
    assert hm.cells["T1595"]["MISSED"] == 1
    assert hm.covered_pct() == round(200 / 3, 1)
    md = hm.to_markdown()
    assert "T1046" in md and "Technique" in md


def test_heatmap_empty():
    hm = AttackHeatmap.from_detections([])
    assert hm.covered_pct() == 0.0 and "No emulated" in hm.to_markdown()


# -- report bundle -------------------------------------------------------
def test_report_bundle_documents_present():
    bundle = Reporter().build(_state())
    docs = bundle.documents
    assert set(docs) == {"executive_summary.md", "technical_report.md",
                         "attack_heatmap.md", "detection_gap_report.md"}
    assert "Detection coverage" in docs["executive_summary.md"]
    assert "Exposed Tomcat Manager" in docs["technical_report.md"]


def test_gap_report_lists_expected_detection():
    bundle = Reporter().build(_state())
    gaps = bundle.data["gaps"]
    assert any(g["technique"] == "T1595" for g in gaps)
    gap = next(g for g in gaps if g["technique"] == "T1595")
    assert "content-discovery" in gap["expected_detection"]
    assert "T1595" in bundle.documents["detection_gap_report.md"]


def test_coverage_and_numeric_verification_in_data():
    bundle = Reporter().build(_state())
    assert bundle.data["detection_coverage"]["coverage_pct"] == 50.0
    assert bundle.data["numeric_verification"]["ok"] is True  # CVE grounded


def test_numeric_verifier_flags_ungrounded_cve_in_report():
    st = _state()
    # a finding citing a CVE that is NOT in grounded_tokens
    f = Finding(title="Bogus", asset_ref="h", source_tool="nuclei",
                cve_ids=["CVE-2099-0001"])
    st.ledger.add(f)
    bundle = Reporter().build(st)
    assert bundle.data["numeric_verification"]["ok"] is False
    assert "CVE-2099-0001" in bundle.data["numeric_verification"]["ungrounded"]


# -- writer --------------------------------------------------------------
def test_bundle_writes_files(tmp_path):
    bundle = Reporter().build(_state())
    paths = bundle.write(tmp_path / "report")
    assert (tmp_path / "report" / "report.json").is_file()
    assert (tmp_path / "report" / "detection_gap_report.md").is_file()
    import json
    data = json.loads((tmp_path / "report" / "report.json").read_text())
    assert data["engagement_id"] == "eng-rep-001"
