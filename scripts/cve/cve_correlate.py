#!/usr/bin/env python3
"""Script de correlation CVE pour les services decouverts (lab local, T07).

Lit un inventaire de services (data/services.json), interroge l'API NVD 2.0
pour chaque service (par mot-cle produit/version) et produit un fichier
data/cves.json contenant les CVE verifiables avec source, niveau de
confiance et service/version concerne.

Contraintes respectees :
- Aucune adresse IP codee en dur (la cible vient de data/services.json).
- Aucun scan, aucun exploit, aucune action intrusive.
- Respect du quota NVD (~5 requetes / 30 s sans cle API) + mise en cache.
- Chaque CVE provient d'une source enregistree (jamais d'identifiant invente).
- Niveaux de confiance : high / medium / low.
- Doublons eliminates par identifiant CVE ; faux positifs signales.
- --dry-run valide l'entree sans aucun appel reseau.

Sources utilisees : NVD NIST (https://nvd.nist.gov) via son API REST 2.0.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

# Permettre l'execution directe (python3 scripts/cve/cve_correlate.py) ainsi
# qu'en module (python3 -m scripts.cve.cve_correlate).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

LOG = logging.getLogger("cve_correlate")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"

# Delai minimal entre deux requetes NVD sans cle API (respecte ~5 req / 30 s).
NVD_MIN_INTERVAL_SEC = 6.0
# Nombre maximal de resultats par requete NVD.
NVD_RESULTS_PER_PAGE = 10
# TTL du cache disque (24 heures). Au-delà, la requete est refaite.
CACHE_TTL_SEC = 24 * 3600

# Mots-cles indiquant un systeme d'exploitation dans une description CVE.
OS_KEYWORDS = [
    "solaris",
    "hp-ux",
    "freebsd",
    "irix",
    "aix",
    "mac os x",
    "macos",
    "windows",
]

# Niveaux de confiance valides.
CONFIDENCE_LEVELS = ("high", "medium", "low")

# Expression pour extraire un numero de version (ex: "4.7p1" -> "4.7").
_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")


def _utc_now() -> str:
    """Retourne l'horodatage UTC au format ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_version(version: str) -> tuple[int, ...]:
    """Convertit une chaine de version en tuple d'entiers pour comparaison.

    Ex: "4.7p1" -> (4, 7, 1) ; "2.3.4" -> (2, 3, 4).
    """
    return tuple(int(x) for x in re.findall(r"\d+", version))


def _version_excluded(
    description: str, version_clean: str, product: str | None = None
) -> bool:
    """Retourne True si version_clean est hors de la plage de versions
    affectee par la CVE, selon les bornes explicites de la description.

    Patterns supportes :
    - "before X", "earlier than X", "prior to X" : affecte les versions < X.
      La cible est exclue si cible >= X.
    - "X and earlier", "X or earlier", "through X", "up to X" : affecte les
      versions <= X. La cible est exclue si cible > X.
    - "from X", "starting at X" : affecte les versions >= X.
      La cible est exclue si cible < X.
    - "X and later", "X and above" : affecte les versions >= X.
      La cible est exclue si cible < X.

    Une borne n'est appliquee que si le produit cible est mentionne a
    proximite de la borne (fenetre de 60 caracteres avant la version),
    afin d'eviter d'appliquer a tort une plage appartenant a un autre
    produit cite dans la meme description (ex: plage Tectia dans une
    fiche OpenSSH). Quand aucun produit n'est passe, les bornes sont
    appliquees (comportement historique).
    """
    if not version_clean:
        return False
    target = _parse_version(version_clean)
    desc_lower = description.lower()
    product_words = [w for w in (product or "").split() if len(w) >= 3]

    def _product_near(match_start: int, window: int = 60) -> bool:
        if not product_words:
            return True  # aucun produit precise : on applique la borne
        start = max(0, match_start - window)
        window_text = desc_lower[start:match_start]
        return any(word in window_text for word in product_words)

    # --- avant X : cible < X affectee ; exclue si cible >= X ---
    for m in re.finditer(r"(?:before|earlier than|prior to)\s+([\d.]+)", desc_lower):
        limit = _parse_version(m.group(1))
        if limit and _product_near(m.start()) and target >= limit:
            return True

    # --- jusqu'a X (inclus) : cible <= X affectee ; exclue si cible > X ---
    for m in re.finditer(
        r"([\d.]+)\s+(?:and earlier|or earlier|through|up to)", desc_lower
    ):
        limit = _parse_version(m.group(1))
        if limit and _product_near(m.start()) and target > limit:
            return True

    # --- a partir de X (inclus) : cible >= X affectee ; exclue si cible < X ---
    for m in re.finditer(r"(?:from|starting at)\s+([\d.]+)", desc_lower):
        limit = _parse_version(m.group(1))
        if limit and _product_near(m.start()) and target < limit:
            return True

    for m in re.finditer(r"([\d.]+)\s+(?:and later|and above)", desc_lower):
        limit = _parse_version(m.group(1))
        if limit and _product_near(m.start()) and target < limit:
            return True

    return False


def _mentioned_versions(desc_lower: str) -> list[tuple[tuple[int, ...], int]]:
    """Extrait les numeros de version (>= 2 composants) avec leur position.

    La position permet de verifier qu'une version mentionnee est associee au
    produit cible (proximite), et non a un autre produit cite dans la meme
    description (ex: versions PHP dans une fiche Apache).
    """
    versions: list[tuple[tuple[int, ...], int]] = []
    for m in re.finditer(r"\d+(?:\.\d+)+", desc_lower):
        parts = tuple(int(x) for x in m.group(0).split("."))
        if len(parts) >= 2:
            versions.append((parts, m.start()))
    return versions


def _version_compatible(mentioned: tuple[int, ...], target: tuple[int, ...]) -> bool:
    """Retourne True si mentioned est la version cible ou un prefixe compatible.

    Ex: mentioned (2, 2) est compatible avec target (2, 2, 8) car 2.2.x
    inclut 2.2.8.
    """
    n = min(len(mentioned), len(target))
    return mentioned[:n] == target[:n]


def build_parser() -> argparse.ArgumentParser:
    """Construit le parseur d'arguments en ligne de commande."""
    parser = argparse.ArgumentParser(
        prog="cve_correlate.py",
        description=(
            "Correle les services decouverts avec des CVE verifiables "
            "(API NVD 2.0, lab local uniquement, aucune IP codee en dur)."
        ),
    )
    parser.add_argument(
        "--services",
        default=str(_REPO_ROOT / "data" / "services.json"),
        help="Fichier inventaire des services (defaut: data/services.json).",
    )
    parser.add_argument(
        "--output",
        default=str(_REPO_ROOT / "data" / "cves.json"),
        help="Fichier de sortie de la correlation CVE (defaut: data/cves.json).",
    )
    parser.add_argument(
        "--cache-dir",
        default=str(_REPO_ROOT / ".cache" / "cve"),
        help="Repertoire de cache des reponses NVD (defaut: .cache/cve).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Valide l'entree et affiche les requetes prevues sans appel reseau.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout en secondes pour chaque requete HTTP (defaut: 30).",
    )
    parser.add_argument(
        "--nvd-api-key",
        default=None,
        help="Cle API NVD optionnelle (augmente le quota de requetes).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Active le journalisation detaillee.",
    )
    return parser


def _setup_logging(verbose: bool) -> None:
    """Configure le journalisation sur la console."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s cve_correlate: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


def load_services(path: Path) -> dict[str, Any]:
    """Charge et valide le fichier data/services.json.

    Leve FileNotFoundError si le fichier est absent, ValueError si le
    contenu n'est pas un inventaire de services valide.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Fichier services introuvable : {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != "1.0":
        raise ValueError(f"schema_version non supporte : {data.get('schema_version')}")
    if not isinstance(data.get("services"), list):
        raise ValueError("Champ 'services' absent ou non liste dans services.json")
    return data


def _product_name(product: str | None, service: str | None) -> str:
    """Retourne le nom de produit le plus pertinent pour une requete NVD.

    Utilise le produit s'il est connu, sinon le nom du service, sans
    nettoyage destructif (eviter de transformer "Linux telnetd" en "Linux").
    """
    name = (product or service or "inconnu").strip()
    return name or "inconnu"


def _extract_version(version: str | None) -> str | None:
    """Extrait le numero de version propre (ex: '4.7p1 Debian' -> '4.7')."""
    if not version:
        return None
    match = _VERSION_RE.search(version)
    return match.group(1) if match else None


def build_queries(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Construit les requetes NVD a partir des services.

    Regroupe les services partageant le meme (produit, version) pour limiter
    le nombre de requetes NVD. Retourne une liste de dictionnaires
    {query, fallback_query, services: [...]}.
    """
    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    for svc in services:
        product = _product_name(svc.get("product"), svc.get("service"))
        version = _extract_version(svc.get("version"))
        key = f"{product}|{version or 'version-inconnue'}"
        query = f"{product} {version}".strip() if version else product
        fallback = product
        if key not in groups:
            groups[key] = {
                "query": query,
                "fallback_query": fallback,
                "services": [],
            }
            order.append(key)
        groups[key]["services"].append(
            {
                "port": svc.get("port"),
                "protocol": svc.get("protocol", "tcp"),
                "service": svc.get("service"),
                "product": svc.get("product"),
                "version": svc.get("version"),
                "cpe": svc.get("cpe", []),
            }
        )

    return [groups[k] for k in order]


def detect_target_os(services: list[dict[str, Any]]) -> str | None:
    """Detecte le systeme d'exploitation cible depuis les CPE des services.

    Retourne 'linux' si un CPE noyau Linux est present, None sinon.
    """
    for svc in services:
        for cpe in svc.get("cpe", []) or []:
            if cpe.startswith("cpe:/o:linux"):
                return "linux"
    return None


class NvdClient:
    """Client minimal pour l'API NVD 2.0 avec limitation de debit et cache."""

    def __init__(
        self,
        timeout: int,
        cache_dir: Path,
        api_key: str | None = None,
        dry_run: bool = False,
    ) -> None:
        self.timeout = timeout
        self.cache_dir = cache_dir
        self.api_key = api_key
        self.dry_run = dry_run
        self._last_request: float | None = None
        self._interval = NVD_MIN_INTERVAL_SEC if api_key is None else 1.0
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"apiKey": api_key})
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, query: str) -> Path:
        digest = hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]
        return self.cache_dir / f"nvd-{digest}.json"

    def _cache_is_fresh(self, path: Path) -> bool:
        if not path.is_file():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            fetched_at = data.get("fetched_at")
            if not fetched_at:
                return False
            fetched = datetime.fromisoformat(fetched_at.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - fetched).total_seconds()
            return age < CACHE_TTL_SEC
        except (json.JSONDecodeError, ValueError, OSError):
            return False

    def _rate_limit(self) -> None:
        """Respecte le delai minimal entre deux requetes NVD."""
        if self._last_request is not None:
            elapsed = time.monotonic() - self._last_request
            if elapsed < self._interval:
                time.sleep(self._interval - elapsed)

    def query(self, keyword: str) -> dict[str, Any] | None:
        """Interroge l'API NVD 2.0 par mot-cle.

        Retourne le dictionnaire de reponse JSON, ou None en cas d'erreur /
        d'indisponibilite (sans lever d'exception, pour ne pas bloquer la
        correlation des autres services).
        """
        if self.dry_run:
            LOG.info("[DRY-RUN] Requete NVD prevue : keywordSearch=%r", keyword)
            return None

        # 1. Cache disque.
        cpath = self._cache_path(keyword)
        if self._cache_is_fresh(cpath):
            LOG.debug("Cache NVD utilise pour %r", keyword)
            return json.loads(cpath.read_text(encoding="utf-8"))

        # 2. Limitation de debit.
        self._rate_limit()

        params = {"keywordSearch": keyword, "resultsPerPage": NVD_RESULTS_PER_PAGE}
        try:
            LOG.info("Requete NVD : keywordSearch=%r", keyword)
            resp = self.session.get(NVD_API_BASE, params=params, timeout=self.timeout)
            self._last_request = time.monotonic()
            if resp.status_code != 200:
                LOG.warning(
                    "NVD a repondu %s pour %r : %s",
                    resp.status_code,
                    keyword,
                    resp.text[:200],
                )
                return None
            data = resp.json()
            # 3. Mise en cache.
            data["fetched_at"] = _utc_now()
            data["_query"] = keyword
            cpath.write_text(
                json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            return data
        except requests.RequestException as exc:
            LOG.warning("Erreur requete NVD pour %r : %s", keyword, exc)
            return None


def _english_description(cve: dict[str, Any]) -> str:
    """Extrait la description anglaise d'une CVE NVD."""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _cvss_and_severity(cve: dict[str, Any]) -> tuple[float | None, str | None]:
    """Extrait le score CVSS et la severite (preference v3.1, puis v3.0, v2)."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")
            if severity is None and score is not None:
                severity = _cvss2_severity(score)
            return score, severity
    return None, None


def _cvss2_severity(score: float) -> str:
    """En deduit la severite CVSS v2 a partir du score (echelle NVD)."""
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _references(cve: dict[str, Any]) -> list[str]:
    """Extrait les URLs de reference d'une CVE NVD."""
    urls: list[str] = []
    for ref in cve.get("references", []):
        url = ref.get("url")
        if url and url not in urls:
            urls.append(url)
    return urls


def _is_linux_target(cpes: list[str], target_os: str | None) -> bool:
    """Retourne True si la cible est identifiee comme Linux."""
    if target_os == "linux":
        return True
    return any(cpe.startswith("cpe:/o:linux") for cpe in cpes or [])


def assess_confidence(
    cve: dict[str, Any],
    service: dict[str, Any],
    target_os: str | None,
) -> tuple[str | None, str]:
    """Evalue le niveau de confiance d'une CVE pour un service.

    Retourne (niveau, motif) avec niveau in {'high','medium','low',None}.
    None signifie un faux positif probable (a exclure / signaler).
    """
    description = _english_description(cve)
    desc_lower = description.lower()
    version = service.get("version")
    version_clean = _extract_version(version)
    product = _product_name(service.get("product"), service.get("service")).lower()
    cpes = service.get("cpe", []) or []
    service_name = (service.get("service") or "").lower()
    target_linux = _is_linux_target(cpes, target_os)

    # --- Faux positif : systeme d'exploitation incompatible ---
    for os_kw in OS_KEYWORDS:
        if os_kw in desc_lower and target_linux and "linux" not in desc_lower:
            return None, (
                f"faux positif probable : CVE cible {os_kw}, "
                "alors que le service tourne sur Linux"
            )

    # --- Correspondance produit / service / version dans la description ---
    product_mentioned = product in desc_lower
    service_mentioned = service_name in desc_lower and len(service_name) > 2
    version_mentioned = (version_clean is not None and version_clean in desc_lower) or (
        version is not None and version in desc_lower
    )

    # --- Version cible vs plage affectee par la CVE ---
    # Une borne explicite (avant / jusqu'a / a partir de) qui place la cible
    # hors de la plage affectee constitue un faux positif probable.
    if version_clean is not None and _version_excluded(
        description, version_clean, product
    ):
        return None, (
            "faux positif probable : version du service hors de la plage "
            "affectee par la CVE"
        )

    # La CVE cite le produit ou le service avec des versions specifiques,
    # mais pas la version cible. Si aucune version mentionnee a proximite du
    # produit n'est compatible avec la cible, la CVE vise probablement
    # d'autres versions (ex: Apache 2.0.39/2.0.40 pour une cible 2.2.8).
    if (
        version_clean is not None
        and not version_mentioned
        and (product_mentioned or service_mentioned)
    ):
        mentioned = _mentioned_versions(desc_lower)
        target = _parse_version(version_clean)
        product_words = [w for w in product.split() if len(w) >= 3]
        near: list[tuple[int, ...]] = []
        for ver, pos in mentioned:
            start = max(0, pos - 60)
            window = desc_lower[start:pos]
            if product_words and any(w in window for w in product_words):
                near.append(ver)
        if near and not any(_version_compatible(m, target) for m in near):
            return None, (
                "faux positif probable : la CVE cible des versions "
                "differentes de la version du service"
            )

    # Faux positif : la CVE decrit explicitement un autre produit comme
    # logiciel vulnerable, le service cible n'etant cite qu'en comparaison.
    # Ex: CVE-2024-27305 cible aiosmtpd et mentionne Postfix seulement comme
    # "autre logiciel SMTP" ; elle ne s'applique pas a Postfix.
    if (
        version_clean is None
        and not product_mentioned
        and service_mentioned
        and service_name in ("smtp", "smtpd")
    ):
        for other_product in ("aiosmtpd",):
            if other_product in desc_lower:
                return None, (
                    f"faux positif probable : la CVE cible {other_product}, "
                    f"pas le service {service_name or product}"
                )

    # Si ni le produit, ni le service, ni la version n'apparait, c'est un
    # faux positif probable (la requete NVD a matche sur un mot-cle sans
    # lien avec le service).
    if not product_mentioned and not service_mentioned and not version_mentioned:
        return None, (
            "faux positif probable : produit/service/version non lies au "
            "service dans la description CVE"
        )

    # --- Niveau de confiance ---
    if version_mentioned and (product_mentioned or service_mentioned):
        return (
            "high",
            "produit/service et version exactes mentions dans la description CVE",
        )
    if version_mentioned:
        return "medium", "version mentionnee dans la description CVE"
    if product_mentioned or service_mentioned:
        return "medium", "produit/service mentionne dans la description CVE"
    return "low", "correspondance approximative (mot-cle uniquement)"


def _cve_entry(
    cve_id: str,
    cve: dict[str, Any],
    confidence: str,
    motif: str,
    services: list[dict[str, Any]],
    matched_on: dict[str, Any],
) -> dict[str, Any]:
    """Construit l'entree CVE normalisee pour data/cves.json."""
    score, severity = _cvss_and_severity(cve)
    return {
        "id": cve_id,
        "source": "nvd",
        "source_url": NVD_DETAIL_URL.format(cve_id=cve_id),
        "cvss": score,
        "severity": severity,
        "confidence": confidence,
        "confidence_motif": motif,  # justifie le niveau de confiance (traceabilite)
        "services": [f"{s['port']}/{s['protocol']}" for s in services],
        "matched_on": matched_on,
        "description": _english_description(cve),
        "references": _references(cve),
        "kev": False,
    }


def correlate(
    services_data: dict[str, Any],
    client: NvdClient,
    target_os: str | None,
) -> dict[str, Any]:
    """Realise la correlation service -> CVE.

    Retourne un dictionnaire pret a etre serialise dans data/cves.json.
    """
    services = services_data.get("services", [])
    target_ip = services_data.get("target", {}).get("ip", "inconnu")
    groups = build_queries(services)

    cves_by_id: dict[str, dict[str, Any]] = {}
    unmatched_services: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []

    for group in groups:
        keyword = group["query"]
        fallback = group["fallback_query"]
        group_services = group["services"]

        resp = client.query(keyword)
        used_query = keyword
        # Fallback : si la requete produit+version ne donne rien, essayer
        # le produit seul (recall plus large).
        if (
            resp is not None
            and resp.get("totalResults", 0) == 0
            and fallback != keyword
        ):
            LOG.debug(
                "Aucun resultat pour %r, essai avec le produit seul %r",
                keyword,
                fallback,
            )
            resp = client.query(fallback)
            used_query = fallback

        if resp is None:
            # Pas de reponse NVD (dry-run ou erreur).
            for svc in group_services:
                unmatched_services.append(
                    {
                        "port": svc["port"],
                        "protocol": svc["protocol"],
                        "service": svc["service"],
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "reason": "aucune requete NVD (dry-run ou erreur reseau)",
                    }
                )
            continue

        total = resp.get("totalResults", 0)
        if total == 0:
            for svc in group_services:
                unmatched_services.append(
                    {
                        "port": svc["port"],
                        "protocol": svc["protocol"],
                        "service": svc["service"],
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "reason": "aucun CVE NVD pour ce produit/version",
                    }
                )
            continue

        for vuln in resp.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id or not re.match(r"^CVE-\d{4}-\d+$", cve_id):
                continue

            # Exclure les CVE rejetees/contestees par le NVD (vulnStatus
            # "Rejected" ou description "Rejected reason: ...").
            if cve.get("vulnStatus") == "Rejected":
                continue
            desc_preview = _english_description(cve)
            if desc_preview.startswith("Rejected reason:"):
                continue

            ref_service = group_services[0]
            confidence, motif = assess_confidence(cve, ref_service, target_os)

            if confidence is None:
                false_positives.append(
                    {
                        "cve": cve_id,
                        "service": f"{ref_service['port']}/{ref_service['protocol']}",
                        "product": ref_service.get("product"),
                        "version": ref_service.get("version"),
                        "motif": motif,
                        "description": _english_description(cve),
                        "source_url": NVD_DETAIL_URL.format(cve_id=cve_id),
                        "matched_on": {"query": used_query},
                    }
                )
                continue

            matched_on = {
                "query": used_query,
                "product": ref_service.get("product"),
                "version": ref_service.get("version"),
                "cpe": ref_service.get("cpe", []),
            }

            if cve_id in cves_by_id:
                entry = cves_by_id[cve_id]
                svc_ref = f"{ref_service['port']}/{ref_service['protocol']}"
                if svc_ref not in entry["services"]:
                    entry["services"].append(svc_ref)
                rank = {c: i for i, c in enumerate(CONFIDENCE_LEVELS)}
                if rank[confidence] < rank[entry["confidence"]]:
                    entry["confidence"] = confidence
                    entry["confidence_motif"] = motif
            else:
                cves_by_id[cve_id] = _cve_entry(
                    cve_id, cve, confidence, motif, group_services, matched_on
                )

    cves = sorted(cves_by_id.values(), key=lambda e: e["id"])

    return {
        "schema_version": "1.0",
        "generated_at": _utc_now(),
        "target": target_ip,
        "source_services": str(services_data.get("_source_file", "data/services.json")),
        "source_proof": services_data.get("_source_proof"),
        "target_os": target_os,
        "cves": cves,
        "unmatched_services": unmatched_services,
        "false_positives": false_positives,
    }


def write_output(data: dict[str, Any], output_path: Path) -> None:
    """Ecrit le fichier de sortie JSON (indentation 2, UTF-8, sans commentaires)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    LOG.info("Resultats ecrits dans %s (%d CVE)", output_path, len(data["cves"]))


def main(argv: list[str] | None = None) -> int:
    """Point d'entree principal du script de correlation CVE."""
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    # 1. Chargement de l'inventaire des services.
    services_path = Path(args.services)
    try:
        services_data = load_services(services_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        LOG.error("%s", exc)
        return 2
    services_data["_source_file"] = str(services_path)
    services_data["_source_proof"] = services_data.get("services", [{}])[0].get(
        "source"
    )

    target_ip = services_data.get("target", {}).get("ip", "inconnu")
    services = services_data.get("services", [])
    target_os = detect_target_os(services)

    # Verification du perimetre (aucune IP publique).
    try:
        import ipaddress

        ip = ipaddress.IPv4Address(target_ip)
        from scripts.recon.scope import is_authorized  # noqa: PLC0415

        if not is_authorized(ip):
            LOG.error("Cible refusee hors perimetre lab : %s", target_ip)
            return 3
    except (ipaddress.AddressValueError, ValueError):
        LOG.warning("Impossible de verifier le perimetre pour %s", target_ip)

    LOG.info(
        "Correlation CVE pour la cible %s (%d services, OS cible: %s)",
        target_ip,
        len(services),
        target_os or "inconnu",
    )

    # 2. Construction des requetes NVD.
    groups = build_queries(services)
    LOG.info(
        "%d requete(s) NVD prevue(s) pour %d service(s)",
        len(groups),
        len(services),
    )

    if args.dry_run:
        LOG.info("=== MODE DRY-RUN : aucun appel reseau ===")
        for group in groups:
            LOG.info(
                "  - keywordSearch=%r (fallback=%r) (services: %s)",
                group["query"],
                group["fallback_query"],
                [f"{s['port']}/{s['protocol']}" for s in group["services"]],
            )
        return 0

    # 3. Requetes NVD et correlation.
    client = NvdClient(
        timeout=args.timeout,
        cache_dir=Path(args.cache_dir),
        api_key=args.nvd_api_key,
        dry_run=False,
    )
    result = correlate(services_data, client, target_os)

    # 4. Ecriture. Le champ confidence_motif est conserve pour la traceabilite
    # de chaque niveau de confiance (recommandation de revue R-006 / F-005).
    write_output(result, Path(args.output))
    LOG.info(
        "Termine : %d CVE, %d services non correspondu, %d faux positifs signales.",
        len(result["cves"]),
        len(result["unmatched_services"]),
        len(result["false_positives"]),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
