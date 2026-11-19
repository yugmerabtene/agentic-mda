#!/usr/bin/env python3
"""Script de reconnaissance parametrable d'une VM Metasploitable (lab local).

Realise :
1. la validation du perimetre de la cible (RFC1918 / loopback uniquement) ;
2. l'execution de nmap (decouverte des ports ouverts et des services) ;
3. la conservation des preuves brutes (nmap .nmap, .xml, .gnmap) horodatees ;
4. la normalisation des services decouverts dans data/services.json.

Ce script n'effectue aucune action intrusive : pas d'exploit, pas de brute
force, pas de modification de service. L'option --dry-run permet de valider
le perimetre et d'afficher la commande prevue sans lancer le moindre scan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Permettre l'execution directe (python3 scripts/recon/recon_scan.py) ainsi
# qu'en module (python3 -m scripts.recon.recon_scan).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.recon.parser import NmapService, parse_nmap_xml, services_to_dict  # noqa: E402
from scripts.recon.scope import ScopeError, validate_target  # noqa: E402

LOG = logging.getLogger("recon_scan")

DEFAULT_PORTS = "1-1024"
DEFAULT_RATE = "1000"
DEFAULT_TIMEOUT = 300  # secondes


def _utc_now() -> str:
    """Retourne l'horodatage UTC au format ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_filename_ts() -> str:
    """Horodatage compact UTC pour les noms de fichiers de preuves."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def build_parser() -> argparse.ArgumentParser:
    """Construit le parseur d'arguments en ligne de commande."""
    parser = argparse.ArgumentParser(
        prog="recon_scan.py",
        description=(
            "Reconnaissance parametrable d'une VM Metasploitable "
            "(lab local uniquement, aucune IP codee en dur)."
        ),
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Adresse IPv4 de la cible (RFC1918 ou loopback uniquement).",
    )
    parser.add_argument(
        "--output",
        default=str(_REPO_ROOT / "evidence" / "raw"),
        help="Repertoire des preuves brutes (defaut: evidence/raw).",
    )
    parser.add_argument(
        "--data-dir",
        default=str(_REPO_ROOT / "data"),
        help="Repertoire de sortie des donnees normalisees (defaut: data).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Valide le perimetre et affiche la commande prevue sans lancer de scan.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="Timeout global en secondes pour nmap (defaut: 300).",
    )
    parser.add_argument(
        "--ports",
        default=DEFAULT_PORTS,
        help="Plage de ports a scanner (defaut: 1-1024).",
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        default=None,
        help="Scanner les N ports les plus courants (alternative a --ports).",
    )
    parser.add_argument(
        "--rate",
        default=DEFAULT_RATE,
        help="Debit minimum nmap --min-rate (defaut: 1000).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Active le journalisation detaillee.",
    )
    return parser


def _setup_logging(verbose: bool, log_path: Path | None = None) -> None:
    """Configure le journalisation horodatée sur la console (et fichier si donne)."""
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        "%(asctime)sZ %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    root = logging.getLogger()
    root.setLevel(level)
    # Nettoie les handlers precedents pour permettre la reconfiguration (tests).
    for handler in list(root.handlers):
        root.removeHandler(handler)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)
    if log_path is not None:
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)


def _is_root() -> bool:
    """Retourne True si le processus est execute en tant que root (Unix)."""
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def build_nmap_command(
    target: str,
    output_base: Path,
    timeout: int,
    ports: str | None,
    top_ports: int | None,
    rate: str,
) -> list[str]:
    """Construit la commande nmap (liste d'arguments, sans shell=True).

    Le scan est non intrusif : -Pn (pas de test ping), -sS si root sinon
    -sT, -sV --version-all pour la detection de versions.
    """
    scan_type = "-sS" if _is_root() else "-sT"
    cmd = [
        "nmap",
        "-Pn",
        scan_type,
        "-sV",
        "--version-all",
        "--max-retries",
        "2",
        "--host-timeout",
        f"{timeout}s",
        "--min-rate",
        rate,
        "-oA",
        str(output_base),
    ]
    if top_ports is not None:
        cmd.extend(["--top-ports", str(top_ports)])
    elif ports is not None:
        cmd.extend(["-p", ports])
    cmd.append(target)
    return cmd


def _sha256_file(path: Path) -> str:
    """Calcule l'empreinte SHA-256 d'un fichier."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(raw_files: list[Path], manifest_path: Path) -> None:
    """Ecrit le manifeste SHA-256 des preuves brutes."""
    lines = []
    for path in raw_files:
        if path.is_file():
            lines.append(f"{_sha256_file(path)}  {path.name}")
    manifest_path.write_text(
        "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
    )


def run_scan(
    target: str,
    output_dir: Path,
    data_dir: Path,
    dry_run: bool,
    timeout: int,
    ports: str | None,
    top_ports: int | None,
    rate: str,
    verbose: bool,
) -> int:
    """Execute (ou simule) la reconnaissance. Retourne un code de sortie."""
    # 1. Validation du perimetre (avant toute chose, meme en dry-run).
    try:
        ip = validate_target(target)
    except ScopeError as exc:
        LOG.error("%s", exc)
        return 2

    LOG.info("Cible valide et dans le perimetre lab : %s", ip)

    if dry_run:
        # Dry-run : aucun scan lance, aucun fichier ecrit.
        output_base = output_dir / f"nmap-{target}-{_utc_filename_ts()}"
        cmd = build_nmap_command(target, output_base, timeout, ports, top_ports, rate)
        LOG.info("=== MODE DRY-RUN : aucun scan lance ===")
        LOG.info("Commande prevue : %s", shlex.join(cmd))
        LOG.info(
            "Preuves brutes prevues : %s.{{nmap,xml,gnmap}}", output_base
        )
        LOG.info("Donnees normalisees prevues : %s/services.json", data_dir)
        return 0

    # 2. Execution reelle de nmap.
    output_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    ts = _utc_filename_ts()
    output_base = output_dir / f"nmap-{target}-{ts}"
    log_path = output_dir / f"recon-{target}-{ts}.log"
    _setup_logging(verbose, log_path)

    cmd = build_nmap_command(target, output_base, timeout, ports, top_ports, rate)
    LOG.info("Lancement de nmap : %s", shlex.join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 60,
        )
    except FileNotFoundError:
        LOG.error("nmap introuvable : installez nmap avant d'executer ce script.")
        return 3
    except subprocess.TimeoutExpired as exc:
        LOG.error("nmap a depasse le timeout (%s s) : %s", timeout, exc)
        return 4

    LOG.info("nmap termine avec le code de sortie %s", result.returncode)
    if result.stdout:
        LOG.debug("stdout nmap :\n%s", result.stdout)
    if result.stderr:
        LOG.debug("stderr nmap :\n%s", result.stderr)

    # 3. Conservation des preuves brutes (nmap -oA produit .nmap, .xml, .gnmap).
    raw_files: list[Path] = []
    for suffix in (".nmap", ".xml", ".gnmap"):
        candidate = Path(f"{output_base}{suffix}")
        if candidate.is_file():
            raw_files.append(candidate)

    manifest_path = output_dir / f"manifest-{target}-{ts}.sha256"
    write_manifest(raw_files, manifest_path)
    if manifest_path.is_file():
        raw_files.append(manifest_path)

    # 4. Normalisation des services depuis le XML nmap.
    xml_path = Path(f"{output_base}.xml")
    services: list[NmapService] = []
    if xml_path.is_file():
        services = parse_nmap_xml(xml_path)
        LOG.info(
            "%s service(s) ouvert(s) normalise(s) depuis %s", len(services), xml_path
        )
    else:
        LOG.warning("Fichier XML nmap introuvable : %s", xml_path)

    target_info = {
        "ip": str(ip),
        "hostname": None,
        "os": None,
    }
    normalized = services_to_dict(services, target_info)
    services_json_path = data_dir / "services.json"
    services_json_path.write_text(
        json.dumps(normalized, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    LOG.info("Donnees normalisees ecrites dans %s", services_json_path)

    return result.returncode


def main(argv: list[str] | None = None) -> int:
    """Point d'entree principal du script."""
    parser = build_parser()
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)

    return run_scan(
        target=args.target,
        output_dir=Path(args.output),
        data_dir=Path(args.data_dir),
        dry_run=args.dry_run,
        timeout=args.timeout,
        ports=args.ports,
        top_ports=args.top_ports,
        rate=args.rate,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    sys.exit(main())
