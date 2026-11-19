"""Tests unitaires du script de correlation CVE (scripts/cve/cve_correlate.py).

Le reseau est mocke : aucun appel NVD n'est reellement lance.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.cve.cve_correlate import (  # noqa: E402
    _parse_version,
    _version_excluded,
    assess_confidence,
    build_parser,
    build_queries,
    correlate,
    detect_target_os,
    load_services,
    main,
)

MINIMAL_SERVICES = {
    "schema_version": "1.0",
    "generated_at": "2026-11-19T10:00:00Z",
    "target": {"ip": "192.168.56.103", "hostname": None, "os": None},
    "services": [
        {
            "port": 21,
            "protocol": "tcp",
            "state": "open",
            "service": "ftp",
            "product": "vsftpd",
            "version": "2.3.4",
            "cpe": ["cpe:/a:vsftpd:vsftpd:2.3.4"],
            "extra_info": {},
            "source": "evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml",
        },
        {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "4.7p1 Debian 8ubuntu1",
            "cpe": ["cpe:/a:openbsd:openssh:4.7p1", "cpe:/o:linux:linux_kernel"],
            "extra_info": {},
            "source": "evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml",
        },
        {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "product": "Apache httpd",
            "version": "2.2.8",
            "cpe": ["cpe:/a:apache:http_server:2.2.8"],
            "extra_info": {},
            "source": "evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml",
        },
    ],
    "unmatched": [],
}


def _make_cve(cve_id, description, vulnStatus="Modified", metrics=None):
    """Construit un dictionnaire CVE NVD minimal pour les tests."""
    return {
        "id": cve_id,
        "vulnStatus": vulnStatus,
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": metrics or {},
        "references": [{"url": f"https://example.com/ref/{cve_id}"}],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_help_exits_zero(capsys) -> None:
    """--help affiche l'aide et quitte avec le code 0."""
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])
    assert exc_info.value.code == 0


def test_missing_services_exits_nonzero(tmp_path) -> None:
    """Un fichier services absent est refuse (code != 0)."""
    code = main(
        [
            "--services",
            str(tmp_path / "inexistant.json"),
            "--output",
            str(tmp_path / "cves.json"),
            "--dry-run",
        ]
    )
    assert code != 0


def test_dry_run_no_network(tmp_path, monkeypatch) -> None:
    """--dry-run ne lance aucun appel HTTP (requests non appele)."""
    with patch("requests.Session.get") as mock_get:
        code = main(
            [
                "--services",
                str(REPO_ROOT / "data" / "services.json"),
                "--output",
                str(tmp_path / "cves.json"),
                "--dry-run",
            ]
        )
    assert code == 0
    mock_get.assert_not_called()


def test_dry_run_public_target_refused(tmp_path) -> None:
    """--dry-run sur une adresse publique est refuse (pas d'appel reseau)."""
    services = dict(MINIMAL_SERVICES)
    services["target"] = {"ip": "8.8.8.8", "hostname": None, "os": None}
    svc_path = tmp_path / "services.json"
    svc_path.write_text(json.dumps(services), encoding="utf-8")
    with patch("requests.Session.get") as mock_get:
        code = main(
            [
                "--services",
                str(svc_path),
                "--output",
                str(tmp_path / "cves.json"),
                "--dry-run",
            ]
        )
    assert code != 0
    mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# Requetes et detection d'OS
# ---------------------------------------------------------------------------


def test_build_queries_groups_same_product() -> None:
    """Les services partageant un produit sont regroupes (une requete)."""
    groups = build_queries(MINIMAL_SERVICES["services"])
    queries = [g["query"] for g in groups]
    assert "vsftpd 2.3.4" in queries
    assert "OpenSSH 4.7" in queries
    assert "Apache httpd 2.2.8" in queries
    # Samba n'est pas dans ce jeu minimal ; verifions juste le regroupement.
    samba_services = MINIMAL_SERVICES["services"] + [
        {
            "port": 139,
            "protocol": "tcp",
            "state": "open",
            "service": "netbios-ssn",
            "product": "Samba smbd",
            "version": "3.X - 4.X",
            "cpe": ["cpe:/a:samba:samba"],
            "extra_info": {},
            "source": "evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml",
        },
        {
            "port": 445,
            "protocol": "tcp",
            "state": "open",
            "service": "netbios-ssn",
            "product": "Samba smbd",
            "version": "3.X - 4.X",
            "cpe": ["cpe:/a:samba:samba"],
            "extra_info": {},
            "source": "evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml",
        },
    ]
    groups = build_queries(samba_services)
    samba_groups = [g for g in groups if g["query"].startswith("Samba")]
    assert len(samba_groups) == 1
    assert len(samba_groups[0]["services"]) == 2


def test_detect_target_os_linux() -> None:
    """Un CPE noyau Linux detecte une cible Linux."""
    assert detect_target_os(MINIMAL_SERVICES["services"]) == "linux"


def test_detect_target_os_none() -> None:
    """Sans CPE Linux, l'OS cible est inconnu."""
    services = [
        {
            "port": 25,
            "protocol": "tcp",
            "state": "open",
            "service": "smtp",
            "product": "Postfix",
            "version": None,
            "cpe": ["cpe:/a:postfix:postfix"],
            "extra_info": {},
            "source": "evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml",
        }
    ]
    assert detect_target_os(services) is None


# ---------------------------------------------------------------------------
# Version et confiance
# ---------------------------------------------------------------------------


def test_parse_version() -> None:
    """_parse_version convertit une chaine en tuple d'entiers."""
    assert _parse_version("4.7p1") == (4, 7, 1)
    assert _parse_version("2.3.4") == (2, 3, 4)
    assert _parse_version("2.2.8") == (2, 2, 8)


def test_version_excluded_before() -> None:
    """'before 4.7' exclut une cible en 4.7 (version pas anterieure)."""
    assert _version_excluded("OpenSSH before 4.7 ...", "4.7") is True
    assert _version_excluded("OpenSSH before 4.8 ...", "4.7") is False


def test_version_excluded_before_target_outside_range() -> None:
    """'before 1.3.11' exclut une cible en 2.2.8 (pas anterieure a 1.3.11)."""
    assert _version_excluded("Apache httpd before 1.3.11 ...", "2.2.8") is True
    # Une cible en 1.3.2 est anterieure a 1.3.11 : elle est affectee, pas exclue.
    assert _version_excluded("Apache httpd before 1.3.11 ...", "1.3.2") is False


def test_version_excluded_through_and_earlier() -> None:
    """'2.0.47 and earlier' exclut une cible en 2.2.8 (superieure a 2.0.47)."""
    assert (
        _version_excluded("Apache HTTP Server 2.0.47 and earlier ...", "2.2.8") is True
    )
    # Une cible en 2.0.47 est dans la plage : pas exclue.
    assert (
        _version_excluded("Apache HTTP Server 2.0.47 and earlier ...", "2.0.47")
        is False
    )


def test_version_excluded_from_and_later() -> None:
    """'from 2.2' exclut une cible en 2.0 (inferieure a 2.2)."""
    assert _version_excluded("OpenSSH from 2.2 ...", "2.0") is True
    # Une cible en 2.2 est dans la plage : pas exclue.
    assert _version_excluded("OpenSSH from 2.2 ...", "2.2") is False


def test_version_excluded_product_proximity() -> None:
    """Une plage Tectia n'exclut pas OpenSSH (produit different, pas proche)."""
    desc = "SSH Tectia 4.0 through 4.4.11; OpenSSH 4.7p1 and possibly other versions"
    assert _version_excluded(desc, "4.7", product="OpenSSH") is False
    # Sans produit precise, la borne est appliquee (comportement historique).
    assert _version_excluded(desc, "4.7") is True


def test_version_excluded_earlier_than_and_prior_to() -> None:
    """Les variantes 'earlier than' et 'prior to' sont detectees."""
    assert _version_excluded("OpenSSH earlier than 4.7 ...", "4.7") is True
    assert _version_excluded("OpenSSH prior to 4.7 ...", "4.7") is True
    assert _version_excluded("OpenSSH earlier than 4.8 ...", "4.7") is False


def test_assess_confidence_false_positive_version_range() -> None:
    """'before 4.7' pour cible 4.7p1 = faux positif (version hors plage)."""
    cve = _make_cve(
        "CVE-2007-4752",
        "ssh in OpenSSH before 4.7 does not properly handle ...",
    )
    svc = MINIMAL_SERVICES["services"][1]  # OpenSSH 4.7p1
    conf, motif = assess_confidence(cve, svc, "linux")
    assert conf is None
    assert "faux positif" in motif


def test_assess_confidence_false_positive_apache_outside_range() -> None:
    """Une CVE Apache pour des versions anterieures exclut Apache 2.2.8."""
    cve = _make_cve(
        "CVE-2000-1206",
        "Vulnerability in Apache httpd before 1.3.11 ...",
    )
    svc = MINIMAL_SERVICES["services"][2]  # Apache httpd 2.2.8
    conf, motif = assess_confidence(cve, svc, "linux")
    assert conf is None
    assert "faux positif" in motif


def test_assess_confidence_false_positive_apache_specific_versions() -> None:
    """Une CVE citant Apache 2.0.39/2.0.40 exclut Apache 2.2.8."""
    cve = _make_cve(
        "CVE-2002-1850",
        "mod_cgi in Apache 2.0.39 and 2.0.40 allows ...",
    )
    svc = MINIMAL_SERVICES["services"][2]  # Apache httpd 2.2.8
    conf, motif = assess_confidence(cve, svc, "linux")
    assert conf is None
    assert "faux positif" in motif


def test_assess_confidence_false_positive_aiosmtpd_not_postfix() -> None:
    """CVE-2024-27305 cible aiosmtpd, pas Postfix : faux positif pour SMTP."""
    cve = _make_cve(
        "CVE-2024-27305",
        "aiosmtpd is a reimplementation of the Python stdlib smtpd.py. "
        "This issue is also existed in other SMTP software like Postfix.",
    )
    svc = {
        "port": 25,
        "protocol": "tcp",
        "state": "open",
        "service": "smtp",
        "product": "Postfix smtpd",
        "version": None,
        "cpe": ["cpe:/a:postfix:postfix"],
        "extra_info": {},
        "source": "evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml",
    }
    conf, motif = assess_confidence(cve, svc, "linux")
    assert conf is None
    assert "aiosmtpd" in motif
    assert "faux positif" in motif


def test_assess_confidence_keeps_real_postfix_cve() -> None:
    """CVE-2023-51764 (Postfix) n'est pas exclue par la regle aiosmtpd."""
    cve = _make_cve(
        "CVE-2023-51764",
        "Postfix through 3.8.5 allows SMTP smuggling ...",
    )
    svc = {
        "port": 25,
        "protocol": "tcp",
        "state": "open",
        "service": "smtp",
        "product": "Postfix smtpd",
        "version": None,
        "cpe": ["cpe:/a:postfix:postfix"],
        "extra_info": {},
        "source": "evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml",
    }
    conf, motif = assess_confidence(cve, svc, "linux")
    assert conf == "medium"


def test_assess_confidence_keeps_apache_php_cve() -> None:
    """CVE-2006-4625 (PHP, versions PHP non compatibles mais loin du produit
    Apache) reste associee au service http (pas de version Apache proche)."""
    cve = _make_cve(
        "CVE-2006-4625",
        "PHP 4.x up to 4.4.4 and PHP 5 up to 5.1.6 allows local users to "
        "bypass certain Apache HTTP Server httpd.conf options ...",
    )
    svc = MINIMAL_SERVICES["services"][2]  # Apache httpd 2.2.8
    conf, motif = assess_confidence(cve, svc, "linux")
    assert conf == "medium"


def test_assess_confidence_high() -> None:
    """Produit + version exacts mentions = confiance elevee."""
    cve = _make_cve(
        "CVE-2011-2523",
        "vsftpd 2.3.4 contains a backdoor.",
    )
    svc = MINIMAL_SERVICES["services"][0]  # vsftpd 2.3.4
    conf, motif = assess_confidence(cve, svc, "linux")
    assert conf == "high"
    assert "version exacte" in motif


def test_assess_confidence_medium_product() -> None:
    """Produit mentionne sans version = confiance moyenne."""
    cve = _make_cve(
        "CVE-XXXX-0001",
        "Apache httpd has a buffer overflow.",
    )
    svc = MINIMAL_SERVICES["services"][2]  # Apache httpd 2.2.8
    conf, motif = assess_confidence(cve, svc, "linux")
    assert conf == "medium"


def test_assess_confidence_false_positive_os() -> None:
    """CVE cible Solaris sur cible Linux = faux positif."""
    cve = _make_cve(
        "CVE-2003-1070",
        "rpcbind for Solaris 2.6 through 9 allows denial of service.",
    )
    svc = {
        "port": 111,
        "protocol": "tcp",
        "state": "open",
        "service": "rpcbind",
        "product": None,
        "version": "2",
        "cpe": ["cpe:/o:linux:linux_kernel"],
        "extra_info": {},
        "source": "evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml",
    }
    conf, motif = assess_confidence(cve, svc, "linux")
    assert conf is None
    assert "faux positif" in motif


def test_assess_confidence_false_positive_apache_before_range() -> None:
    """'before 4.7' pour cible 4.7p1 = faux positif (version hors plage)."""
    cve = _make_cve(
        "CVE-2007-4752",
        "ssh in OpenSSH before 4.7 does not properly handle ...",
    )
    svc = MINIMAL_SERVICES["services"][1]  # OpenSSH 4.7p1
    conf, motif = assess_confidence(cve, svc, "linux")
    assert conf is None
    assert "faux positif" in motif


def test_assess_confidence_no_link() -> None:
    """Aucun produit/service/version dans la description = faux positif."""
    cve = _make_cve(
        "CVE-XXXX-9999",
        "Unrelated vulnerability in some other product.",
    )
    svc = MINIMAL_SERVICES["services"][0]  # vsftpd
    conf, motif = assess_confidence(cve, svc, "linux")
    assert conf is None
    assert "faux positif" in motif


# ---------------------------------------------------------------------------
# Correlation avec NVD mocke
# ---------------------------------------------------------------------------


def _nvd_response(cves):
    return {
        "totalResults": len(cves),
        "vulnerabilities": [{"cve": c} for c in cves],
    }


def test_correlate_dedup_and_false_positives(tmp_path, monkeypatch) -> None:
    """Doublonnes eliminees, faux positifs signales, CVE rejetees exclues."""
    cve_good = _make_cve(
        "CVE-2011-2523",
        "vsftpd 2.3.4 contains a backdoor.",
        metrics={
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
            ]
        },
    )
    cve_fp = _make_cve(
        "CVE-2007-4752",
        "ssh in OpenSSH before 4.7 does not properly handle ...",
    )
    cve_rejected = _make_cve(
        "CVE-2007-4044",
        "Rejected reason: ...",
        vulnStatus="Rejected",
    )

    class FakeResp:
        def __init__(self, data):
            self.data = data
            self.status_code = 200

        def json(self):
            return self.data

    calls = []

    def fake_get(url, params, timeout):
        calls.append(params.get("keywordSearch"))
        kw = params.get("keywordSearch")
        if kw == "vsftpd 2.3.4":
            return FakeResp(_nvd_response([cve_good, cve_fp, cve_rejected]))
        return FakeResp(_nvd_response([]))

    with patch("requests.Session.get", side_effect=fake_get):
        from scripts.cve.cve_correlate import NvdClient

        client = NvdClient(timeout=5, cache_dir=tmp_path / "cache", dry_run=False)
        result = correlate(MINIMAL_SERVICES, client, "linux")

    ids = [c["id"] for c in result["cves"]]
    assert "CVE-2011-2523" in ids
    assert "CVE-2007-4752" not in ids  # faux positif (version hors plage)
    assert "CVE-2007-4044" not in ids  # CVE rejetee exclue
    fp_ids = [fp["cve"] for fp in result["false_positives"]]
    assert "CVE-2007-4752" in fp_ids
    # Le CVE bon est associe au service 21/tcp
    entry = next(c for c in result["cves"] if c["id"] == "CVE-2011-2523")
    assert entry["services"] == ["21/tcp"]
    assert entry["confidence"] == "high"
    assert entry["source"] == "nvd"
    assert entry["source_url"].startswith("https://nvd.nist.gov/vuln/detail/")


def test_correlate_unmatched_when_no_cve(tmp_path, monkeypatch) -> None:
    """Aucun CVE NVD => service signale dans unmatched_services."""

    class FakeResp:
        def __init__(self):
            self.status_code = 200

        def json(self):
            return {"totalResults": 0, "vulnerabilities": []}

    with patch("requests.Session.get", return_value=FakeResp()):
        from scripts.cve.cve_correlate import NvdClient

        client = NvdClient(timeout=5, cache_dir=tmp_path / "cache", dry_run=False)
        result = correlate(MINIMAL_SERVICES, client, "linux")

    assert len(result["cves"]) == 0
    assert len(result["unmatched_services"]) == 3


# ---------------------------------------------------------------------------
# Ecriture et chargement
# ---------------------------------------------------------------------------


def test_load_services_valid(tmp_path) -> None:
    """load_services retourne un dictionnaire valide."""
    path = tmp_path / "services.json"
    path.write_text(json.dumps(MINIMAL_SERVICES), encoding="utf-8")
    data = load_services(path)
    assert data["schema_version"] == "1.0"
    assert len(data["services"]) == 3


def test_load_services_invalid_schema(tmp_path) -> None:
    """Un schema_version non supporte leve une ValueError."""
    path = tmp_path / "services.json"
    bad = dict(MINIMAL_SERVICES)
    bad["schema_version"] = "2.0"
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError):
        load_services(path)


def test_write_output_structure(tmp_path) -> None:
    """write_output produit un JSON valide avec les champs attendus."""
    from scripts.cve.cve_correlate import write_output

    result = {
        "schema_version": "1.0",
        "generated_at": "2026-11-19T10:00:00Z",
        "target": "192.168.56.103",
        "cves": [],
        "unmatched_services": [],
        "false_positives": [],
    }
    out = tmp_path / "cves.json"
    write_output(result, out)
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert data["target"] == "192.168.56.103"
