"""Tests d'integration du script de reconnaissance (scripts/recon/recon_scan.py).

Ces tests sont marques @pytest.mark.integration et ne sont pas executes par
defaut (voir pytest.ini). Ils peuvent invoquer nmap localement mais ne
scannent jamais la cible lab 192.168.56.101 dans le cadre de T03 (developpement
uniquement). La cible reel est reservee a T05.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.recon.recon_scan import main  # noqa: E402

NMAP_BIN = shutil.which("nmap")

pytestmark = pytest.mark.integration


@pytest.fixture
def out_dirs(tmp_path: Path) -> tuple[Path, Path]:
    """Repertoires de sortie temporaires (ne touche pas a evidence/raw ni data)."""
    raw = tmp_path / "raw"
    data = tmp_path / "data"
    raw.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)
    return raw, data


def test_nmap_binary_available() -> None:
    """nmap doit etre installe pour les tests d'integration reel."""
    assert NMAP_BIN is not None, "nmap introuvable dans le PATH"


def test_dry_run_valid_target_creates_no_files(out_dirs) -> None:
    """--dry-run sur 192.168.56.101 valide le perimetre sans ecrire de preuve."""
    raw, data = out_dirs
    code = main(
        [
            "--target",
            "192.168.56.101",
            "--dry-run",
            "--output",
            str(raw),
            "--data-dir",
            str(data),
        ]
    )
    assert code == 0
    assert not any(raw.iterdir()), "aucune preuve brute en dry-run"
    assert not any(data.iterdir()), "aucune donnee normalisee en dry-run"


def test_dry_run_public_target_refused(out_dirs) -> None:
    """--dry-run sur une adresse publique est refuse sans lancer de scan."""
    raw, data = out_dirs
    code = main(
        [
            "--target",
            "8.8.8.8",
            "--dry-run",
            "--output",
            str(raw),
            "--data-dir",
            str(data),
        ]
    )
    assert code != 0
    assert not any(raw.iterdir())
    assert not any(data.iterdir())


@pytest.mark.skipif(NMAP_BIN is None, reason="nmap non installe")
def test_real_scan_loopback_only(out_dirs) -> None:
    """Scan reel sur la boucleback (127.0.0.1) uniquement, jamais sur 192.168.56.101.

    Valide la chaine complete : execution nmap, preuves brutes, normalisation.
    """
    raw, data = out_dirs
    code = main(
        [
            "--target",
            "127.0.0.1",
            "--output",
            str(raw),
            "--data-dir",
            str(data),
            "--timeout",
            "30",
            "--ports",
            "22,80",
            "--rate",
            "1000",
        ]
    )
    assert code == 0, "nmap doit terminer sans erreur sur la boucleback"

    xml_files = list(raw.glob("nmap-127.0.0.1-*.xml"))
    assert len(xml_files) == 1, f"une preuve brute XML attendue, trouve : {xml_files}"
    assert len(list(raw.glob("manifest-127.0.0.1-*.sha256"))) == 1

    services_json = data / "services.json"
    assert services_json.is_file()
    data_json = json.loads(services_json.read_text(encoding="utf-8"))
    assert data_json["schema_version"] == "1.0"
    assert data_json["target"]["ip"] == "127.0.0.1"
    assert isinstance(data_json["services"], list)
    assert data_json["unmatched"] == []
