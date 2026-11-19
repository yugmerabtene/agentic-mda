"""Tests unitaires de l'interface CLI (scripts/recon/recon_scan.py).

Le reseau est mocke : aucun appel nmap n'est reellement lance et aucune
preuve brute n'est ecrite sur disque.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.recon.recon_scan import build_parser, main  # noqa: E402

MINIMAL_NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" xmloutputversion="1.05">
  <host starttime="1" endtime="2">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.56.101" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open" reason="syn-ack"/>
        <service name="ftp" product="vsftpd" version="2.3.4">
          <cpe>cpe:/a:vsftpd:vsftpd:2.3.4</cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_help_exits_zero(capsys) -> None:
    """--help affiche l'aide et quitte avec le code 0."""
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])
    assert exc_info.value.code == 0


def test_missing_target_exits_nonzero() -> None:
    """L'absence de --target est une erreur (code != 0)."""
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args([])
    assert exc_info.value.code != 0


def test_dry_run_valid_target_no_scan(tmp_path) -> None:
    """--dry-run sur une cible privee ne lance pas nmap et n'ecrit aucune preuve."""
    with patch(
        "subprocess.run",
        side_effect=AssertionError("nmap ne doit pas etre appele en dry-run"),
    ):
        code = main(
            [
                "--target",
                "192.168.56.101",
                "--dry-run",
                "--output",
                str(tmp_path),
                "--data-dir",
                str(tmp_path),
            ]
        )
    assert code == 0
    assert list(tmp_path.iterdir()) == [], (
        "aucune preuve brute ne doit etre ecrite en dry-run"
    )


def test_dry_run_public_target_refused(tmp_path) -> None:
    """--dry-run sur une adresse publique est refuse (code != 0, pas de scan)."""
    with patch("subprocess.run") as mock_run:
        code = main(
            [
                "--target",
                "8.8.8.8",
                "--dry-run",
                "--output",
                str(tmp_path),
                "--data-dir",
                str(tmp_path),
            ]
        )
    assert code != 0
    mock_run.assert_not_called()
    assert list(tmp_path.iterdir()) == []


def test_real_mode_creates_evidence_and_normalized(tmp_path, monkeypatch) -> None:
    """Mode reel avec nmap mocke : preuves brutes + donnees normalisees ecrites."""

    def fake_run(cmd, **kwargs):
        # Simule nmap qui cree ses fichiers de sortie -oA.
        base_index = cmd.index("-oA")
        base = cmd[base_index + 1]
        for suffix, content in (
            (".nmap", ""),
            (".gnmap", ""),
            (".xml", MINIMAL_NMAP_XML),
        ):
            Path(f"{base}{suffix}").write_text(content, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("subprocess.run", fake_run)

    code = main(
        [
            "--target",
            "192.168.56.101",
            "--output",
            str(tmp_path),
            "--data-dir",
            str(tmp_path),
            "--timeout",
            "10",
        ]
    )
    assert code == 0

    # Preuves brutes presentes.
    xml_files = list(tmp_path.glob("nmap-192.168.56.101-*.xml"))
    assert len(xml_files) == 1
    assert len(list(tmp_path.glob("manifest-192.168.56.101-*.sha256"))) == 1

    # Donnees normalisees presentes et coherentes.
    services_json = tmp_path / "services.json"
    assert services_json.is_file()
    data = json.loads(services_json.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert data["target"]["ip"] == "192.168.56.101"
    assert len(data["services"]) == 1
    assert data["services"][0]["service"] == "ftp"
    assert data["services"][0]["product"] == "vsftpd"
    assert data["services"][0]["version"] == "2.3.4"
    assert data["services"][0]["source"].endswith(".xml")
