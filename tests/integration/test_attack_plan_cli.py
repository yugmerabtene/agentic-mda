"""Tests d'integration : validation du plan MITRE sur les artefacts reels.

Ces tests lisent les fichiers locaux (plans/, data/) mais ne contactent pas
la cible du lab. Marque : integration.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_validate_attack_plan_real_artifacts():
    """Le validateur doit retourner 0 sur les artefacts reels du depot."""
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "mitre" / "validate_attack_plan.py"),
        "--plan",
        str(ROOT / "plans" / "attack-plan.json"),
        "--markdown",
        str(ROOT / "plans" / "attack-plan.md"),
        "--services",
        str(ROOT / "data" / "services.json"),
        "--cves",
        str(ROOT / "data" / "cves.json"),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Plan MITRE ATT&CK valide" in result.stdout


@pytest.mark.integration
def test_attack_plan_json_is_valid_json():
    import json

    with (ROOT / "plans" / "attack-plan.json").open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["schema_version"] == "1.0"
    assert data["target"]["ip"] == "192.168.56.103"
    phases = data["phases"]
    assert len(phases) == 8
    step_ids = [s["id"] for p in phases for s in p["steps"]]
    assert len(step_ids) == len(set(step_ids))
