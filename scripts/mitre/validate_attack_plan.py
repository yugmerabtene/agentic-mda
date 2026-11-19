#!/usr/bin/env python3
"""Validation du plan d'attaque MITRE ATT&CK (plans/attack-plan.json).

Verifications :
- JSON valide UTF-8 et schema minimal respecte
- unicite des IDs d'etapes
- format des IDs de technique Txxxx(.xxx) et tactiques presentes
- cross-reference des CVE avec data/cves.json
- cross-reference des services avec data/services.json
- cohérence JSON <-> Markdown (plans/attack-plan.md)

Code de sortie non nul en cas d'erreur.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
REQUIRED_STEP_FIELDS = [
    "id",
    "objective",
    "technique",
    "tools",
    "preconditions",
    "expected_evidence",
    "risk",
    "stop_conditions",
    "requires_user_approval",
]


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def extract_markdown_ids(md_path: Path) -> list[str]:
    """Extrait les IDs d'etapes presentes dans le Markdown (Sx.y)."""
    text = md_path.read_text(encoding="utf-8")
    return sorted(set(re.findall(r"\bS\d+\.\d+\b", text)))


def extract_markdown_cves(md_path: Path) -> list[str]:
    text = md_path.read_text(encoding="utf-8")
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))


def extract_markdown_techniques(md_path: Path) -> list[str]:
    text = md_path.read_text(encoding="utf-8")
    return sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)))


def validate(
    plan_path: Path = Path("plans/attack-plan.json"),
    md_path: Path = Path("plans/attack-plan.md"),
    services_path: Path = Path("data/services.json"),
    cves_path: Path = Path("data/cves.json"),
) -> list[str]:
    errors: list[str] = []

    plan = load_json(plan_path)
    services_data = load_json(services_path)
    cves_data = load_json(cves_path)

    # Champs de niveau racine attendus
    for field in ("schema_version", "mission", "target", "generated_at", "phases"):
        if field not in plan:
            errors.append(f"champ racine manquant: {field}")

    known_services = {
        f"{s['port']}/{s['protocol']}" for s in services_data.get("services", [])
    }
    known_cves = {c["id"] for c in cves_data.get("cves", [])}

    step_ids: list[str] = []
    used_cves: set[str] = set()
    used_services: set[str] = set()
    used_techniques: set[str] = set()

    for phase in plan.get("phases", []):
        for field in ("id", "name", "tactic", "steps"):
            if field not in phase:
                errors.append(f"phase {phase.get('id', '?')}: champ manquant {field}")
                continue
        tactic = phase.get("tactic", {})
        if not isinstance(tactic, dict) or not tactic.get("id") or not tactic.get("name"):
            errors.append(f"phase {phase.get('id', '?')}: tactic invalide")

        for step in phase.get("steps", []):
            sid = step.get("id")
            step_ids.append(sid)
            for field in REQUIRED_STEP_FIELDS:
                if field not in step:
                    errors.append(f"etape {sid}: champ obligatoire manquant {field}")

            tech = step.get("technique", {})
            tid = tech.get("id", "")
            if not TECHNIQUE_RE.fullmatch(tid):
                errors.append(f"etape {sid}: ID technique invalide '{tid}'")
            else:
                used_techniques.add(tid)
            if not tech.get("name"):
                errors.append(f"etape {sid}: nom de technique manquant")

            for cve in step.get("cves", []):
                used_cves.add(cve)
                if cve not in known_cves:
                    errors.append(f"etape {sid}: CVE inconnue dans data/cves.json: {cve}")

            for svc in step.get("services", []):
                used_services.add(svc)
                if svc not in known_services:
                    errors.append(
                        f"etape {sid}: service inconnu dans data/services.json: {svc}"
                    )

            if not isinstance(step.get("requires_user_approval"), bool):
                errors.append(f"etape {sid}: requires_user_approval doit etre un booléen")

    if len(step_ids) != len(set(step_ids)):
        dups = [sid for sid in step_ids if step_ids.count(sid) > 1]
        errors.append(f"IDs d'etapes en double: {sorted(set(dups))}")

    missing_cves = known_cves - used_cves
    if missing_cves:
        errors.append(f"CVE de data/cves.json non citees dans le plan: {sorted(missing_cves)}")

    unknown_services = used_services - known_services
    if unknown_services:
        errors.append(f"Services cites non presents dans data/services.json: {sorted(unknown_services)}")

    # Cohérence JSON <-> Markdown
    if md_path.exists():
        md_step_ids = extract_markdown_ids(md_path)
        json_step_ids = sorted(step_ids)
        if md_step_ids != json_step_ids:
            errors.append(
                "IDs d'etapes JSON/Markdown incoherents: "
                f"JSON={json_step_ids}, Markdown={md_step_ids}"
            )

        md_cves = extract_markdown_cves(md_path)
        if sorted(used_cves) != md_cves:
            errors.append(
                "CVE JSON/Markdown incoherentes: "
                f"JSON={sorted(used_cves)}, Markdown={md_cves}"
            )

        md_techniques = extract_markdown_techniques(md_path)
        if sorted(used_techniques) != md_techniques:
            errors.append(
                "Techniques JSON/Markdown incoherentes: "
                f"JSON={sorted(used_techniques)}, Markdown={md_techniques}"
            )
    else:
        errors.append(f"fichier Markdown manquant: {md_path}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Valide plans/attack-plan.json (schema, IDs, CVE, services, cohérence MD)"
    )
    parser.add_argument("--plan", default="plans/attack-plan.json", help="chemin du plan JSON")
    parser.add_argument("--markdown", default="plans/attack-plan.md", help="chemin du plan Markdown")
    parser.add_argument("--services", default="data/services.json", help="chemin des services")
    parser.add_argument("--cves", default="data/cves.json", help="chemin des CVE")
    args = parser.parse_args()

    errors = validate(
        Path(args.plan),
        Path(args.markdown),
        Path(args.services),
        Path(args.cves),
    )

    if errors:
        print("ERREURS DE VALIDATION :")
        for err in errors:
            print(f" - {err}")
        return 1

    plan = load_json(Path(args.plan))
    n_steps = sum(len(p.get("steps", [])) for p in plan.get("phases", []))
    n_techniques = len(
        {
            s["technique"]["id"]
            for p in plan.get("phases", [])
            for s in p.get("steps", [])
        }
    )
    print("Plan MITRE ATT&CK valide :")
    print(f" - phases: {len(plan.get('phases', []))}")
    print(f" - etapes: {n_steps}")
    print(f" - techniques uniques: {n_techniques}")
    print(f" - cves citees: {len(load_json(Path(args.cves)).get('cves', []))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
