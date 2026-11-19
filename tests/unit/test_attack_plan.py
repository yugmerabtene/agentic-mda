"""Tests unitaires pour scripts/mitre/validate_attack_plan.py.

Ces tests ne touchent ni au reseau ni a la cible du lab : ils utilisent des
fichiers temporaires fabriques en memoire/sur disque temporaire.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

from mitre.validate_attack_plan import (  # noqa: E402
    TECHNIQUE_RE,
    extract_markdown_cves,
    extract_markdown_ids,
    extract_markdown_techniques,
    validate,
)

FIX = Path(__file__).resolve().parent / "fixtures"


def _write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _base_plan() -> dict:
    return {
        "schema_version": "1.0",
        "mission": "test",
        "target": {"ip": "192.168.56.103", "name": "Meta"},
        "generated_at": "2026-11-19T12:00:00Z",
        "phases": [
            {
                "id": "P1",
                "name": "Reconnaissance",
                "tactic": {"id": "TA0043", "name": "Reconnaissance"},
                "steps": [
                    {
                        "id": "S1.1",
                        "objective": "obj",
                        "technique": {"id": "T1595.002", "name": "Vulnerability Scanning"},
                        "services": ["80/tcp"],
                        "cves": ["CVE-1999-0236"],
                        "tools": ["nmap"],
                        "preconditions": ["pre"],
                        "expected_evidence": ["evidence/raw/x.xml"],
                        "detection": ["det"],
                        "risk": "low",
                        "stop_conditions": ["stop"],
                        "requires_user_approval": False,
                    }
                ],
            }
        ],
    }


def test_technique_regex_valid_ids():
    for tid in ["T1595.002", "T1190", "T1499", "T1021.004"]:
        assert TECHNIQUE_RE.fullmatch(tid), tid
    for bad in ["T1.2.3", "TX190", "T119", "", "T1595.0", "T1595.0023"]:
        assert not TECHNIQUE_RE.fullmatch(bad), bad


def test_extract_markdown_ids(tmp_path):
    md = tmp_path / "plan.md"
    md.write_text(
        "# Plan\n\n### S1.1 — test\n\n### S2.1 — autre\n\n### S1.1 — duplicate\n",
        encoding="utf-8",
    )
    assert extract_markdown_ids(md) == ["S1.1", "S2.1"]


def test_extract_markdown_cves_and_techniques(tmp_path):
    md = tmp_path / "plan.md"
    md.write_text(
        "CVE-1999-0236 et CVE-2011-2523 ; T1595.002 et T1190 ; T1595.002 en double.",
        encoding="utf-8",
    )
    assert extract_markdown_cves(md) == ["CVE-1999-0236", "CVE-2011-2523"]
    assert extract_markdown_techniques(md) == ["T1190", "T1595.002"]


def test_valid_plan_passes(tmp_path):
    plan_p = _write_tmp(tmp_path, "plan.json", json.dumps(_base_plan()))
    svc_p = _write_tmp(
        tmp_path,
        "services.json",
        json.dumps({"services": [{"port": 80, "protocol": "tcp"}]}),
    )
    cve_p = _write_tmp(
        tmp_path,
        "cves.json",
        json.dumps({"cves": [{"id": "CVE-1999-0236"}]}),
    )
    md_p = _write_tmp(
        tmp_path,
        "plan.md",
        "# Plan\n\n### S1.1 — test\n\nCVE-1999-0236 ; T1595.002\n",
    )
    errors = validate(plan_p, md_p, svc_p, cve_p)
    assert errors == [], errors


def test_duplicate_step_ids_rejected(tmp_path):
    plan = _base_plan()
    plan["phases"][0]["steps"].append(dict(plan["phases"][0]["steps"][0], id="S1.1"))
    plan_p = _write_tmp(tmp_path, "plan.json", json.dumps(plan))
    svc_p = _write_tmp(tmp_path, "services.json", json.dumps({"services": []}))
    cve_p = _write_tmp(tmp_path, "cves.json", json.dumps({"cves": []}))
    md_p = _write_tmp(tmp_path, "plan.md", "# Plan\n\n### S1.1 — test\n")
    errors = validate(plan_p, md_p, svc_p, cve_p)
    assert any("double" in e for e in errors), errors


def test_unknown_cve_rejected(tmp_path):
    plan = _base_plan()
    plan["phases"][0]["steps"][0]["cves"] = ["CVE-9999-9999"]
    plan_p = _write_tmp(tmp_path, "plan.json", json.dumps(plan))
    svc_p = _write_tmp(tmp_path, "services.json", json.dumps({"services": []}))
    cve_p = _write_tmp(tmp_path, "cves.json", json.dumps({"cves": []}))
    md_p = _write_tmp(tmp_path, "plan.md", "# Plan\n\n### S1.1 — test\n")
    errors = validate(plan_p, md_p, svc_p, cve_p)
    assert any("CVE inconnue" in e for e in errors), errors


def test_unknown_service_rejected(tmp_path):
    plan = _base_plan()
    plan["phases"][0]["steps"][0]["services"] = ["99999/tcp"]
    plan_p = _write_tmp(tmp_path, "plan.json", json.dumps(plan))
    svc_p = _write_tmp(tmp_path, "services.json", json.dumps({"services": []}))
    cve_p = _write_tmp(tmp_path, "cves.json", json.dumps({"cves": [{"id": "CVE-1999-0236"}]}))
    md_p = _write_tmp(tmp_path, "plan.md", "# Plan\n\n### S1.1 — test\n")
    errors = validate(plan_p, md_p, svc_p, cve_p)
    assert any("service inconnu" in e for e in errors), errors


def test_invalid_technique_id_rejected(tmp_path):
    plan = _base_plan()
    plan["phases"][0]["steps"][0]["technique"]["id"] = "T99999"
    plan_p = _write_tmp(tmp_path, "plan.json", json.dumps(plan))
    svc_p = _write_tmp(tmp_path, "services.json", json.dumps({"services": [{"port": 80, "protocol": "tcp"}]}))
    cve_p = _write_tmp(tmp_path, "cves.json", json.dumps({"cves": []}))
    md_p = _write_tmp(tmp_path, "plan.md", "# Plan\n\n### S1.1 — test\n")
    errors = validate(plan_p, md_p, svc_p, cve_p)
    assert any("technique invalide" in e for e in errors), errors


def test_uncited_cve_rejected(tmp_path):
    plan = _base_plan()
    plan_p = _write_tmp(tmp_path, "plan.json", json.dumps(plan))
    svc_p = _write_tmp(tmp_path, "services.json", json.dumps({"services": [{"port": 80, "protocol": "tcp"}]}))
    cve_p = _write_tmp(
        tmp_path,
        "cves.json",
        json.dumps({"cves": [{"id": "CVE-1999-0236"}, {"id": "CVE-2011-2523"}]}),
    )
    md_p = _write_tmp(tmp_path, "plan.md", "# Plan\n\n### S1.1 — test\n")
    errors = validate(plan_p, md_p, svc_p, cve_p)
    assert any("non citees" in e for e in errors), errors


def test_json_markdown_step_ids_mismatch_rejected(tmp_path):
    plan_p = _write_tmp(tmp_path, "plan.json", json.dumps(_base_plan()))
    svc_p = _write_tmp(tmp_path, "services.json", json.dumps({"services": [{"port": 80, "protocol": "tcp"}]}))
    cve_p = _write_tmp(
        tmp_path,
        "cves.json",
        json.dumps({"cves": [{"id": "CVE-1999-0236"}]}),
    )
    md_p = _write_tmp(tmp_path, "plan.md", "# Plan\n\n### S9.9 — absent du JSON\n")
    errors = validate(plan_p, md_p, svc_p, cve_p)
    assert any("incoherents" in e for e in errors), errors
