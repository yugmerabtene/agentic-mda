"""Tests unitaires de l'environnement de travail (T02).

Ces tests ne dépendent pas du lab (pas de réseau, pas de cible). Ils valident
que l'environnement de développement est correctement configuré :
- version Python >= 3.11,
- presence de requirements.txt valide,
- presence des repertoires de l'arborescence de travail.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

REQUIRED_DIRS = [
    "scripts/recon",
    "scripts/cve",
    "scripts/report",
    "tests/unit",
    "tests/integration",
    "tests/e2e",
    "configs",
    "data",
    "evidence/raw",
    "evidence/normalized",
    "plans",
    "reports",
    "review",
]


def test_python_version_minimum() -> None:
    """La version de Python doit etre >= 3.11 (convention AGENTS.md)."""
    major, minor = sys.version_info[:2]
    assert (major, minor) >= (3, 11), f"Python {major}.{minor} < 3.11"


def test_requirements_txt_exists() -> None:
    """Le fichier requirements.txt doit exister a la racine du depot."""
    req = REPO_ROOT / "requirements.txt"
    assert req.is_file(), "requirements.txt manquant a la racine du depot"
    content = req.read_text(encoding="utf-8")
    assert content.strip(), "requirements.txt est vide"


def test_worktree_directories_exist() -> None:
    """Tous les repertoires de l'arborescence de travail doivent exister."""
    for rel in REQUIRED_DIRS:
        assert (REPO_ROOT / rel).is_dir(), f"Repertoire manquant : {rel}"


def test_no_hardcoded_target_ip_in_requirements() -> None:
    """requirements.txt ne doit pas contenir d'adresse IP cible (pas de secret/perimetre)."""
    req = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert "192.168.56.101" not in req
