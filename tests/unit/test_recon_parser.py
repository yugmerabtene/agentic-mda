"""Tests unitaires du parseur XML nmap (scripts/recon/parser.py).

Aucun reseau n'est sollicite : un document XML minimal est analyse en memoire.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.recon.parser import NmapService, parse_nmap_xml, services_to_dict  # noqa: E402

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -Pn -sS -sV 192.168.56.101" start="1" startstr="..." version="7.94" xmloutputversion="1.05">
  <host starttime="1" endtime="2">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.56.101" addrtype="ipv4" vendor="..."/>
    <hostnames>
      <hostname name="metasploitable" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ftp" product="vsftpd" version="2.3.4" extrainfo="..." ostype="Linux">
          <cpe>cpe:/a:vsftpd:vsftpd:2.3.4</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="4.7p1 Debian-8ubuntu1">
          <cpe>cpe:/a:openbsd:openssh:4.7p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset"/>
        <service name="http" product="Apache" version="2.2"/>
      </port>
    </ports>
  </host>
  <host starttime="1" endtime="2">
    <status state="up" reason="arp-response"/>
    <address addr="192.168.56.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _write_xml(tmp_path: Path, content: str = NMAP_XML) -> Path:
    xml_path = tmp_path / "nmap-192.168.56.101-20260101T000000Z.xml"
    xml_path.write_text(content, encoding="utf-8")
    return xml_path


def test_parse_nmap_xml_extracts_open_services(tmp_path) -> None:
    """Seuls les ports ouverts sont extraits, avec produit, version et CPE."""
    xml_path = _write_xml(tmp_path)
    services = parse_nmap_xml(xml_path)

    # 2 services ouverts sur 192.168.56.101 + 1 sur 192.168.56.1 = 3 total.
    assert len(services) == 3

    ftp = next(s for s in services if s.port == 21 and s.protocol == "tcp")
    assert ftp.state == "open"
    assert ftp.service == "ftp"
    assert ftp.product == "vsftpd"
    assert ftp.version == "2.3.4"
    assert ftp.cpe == ["cpe:/a:vsftpd:vsftpd:2.3.4"]
    assert ftp.source == str(xml_path)


def test_closed_port_ignored(tmp_path) -> None:
    """Un port ferme ne doit pas apparaitre dans les services."""
    xml_path = _write_xml(tmp_path)
    services = parse_nmap_xml(xml_path)
    assert all(s.port != 80 for s in services)


def test_parse_missing_file_raises(tmp_path) -> None:
    """L'absence du fichier XML leve une erreur."""
    missing = tmp_path / "nmap-inexistant.xml"
    with pytest.raises(FileNotFoundError):
        parse_nmap_xml(missing)


def test_services_to_dict_structure() -> None:
    """services_to_dict produit le dictionnaire schema data/services.json."""
    services = [
        NmapService(
            port=21,
            protocol="tcp",
            state="open",
            service="ftp",
            product="vsftpd",
            version="2.3.4",
            extrainfo="...",
            cpe=["cpe:/a:vsftpd:vsftpd:2.3.4"],
            source="evidence/raw/nmap-192.168.56.101-20260101T000000Z.xml",
        )
    ]
    target = {"ip": "192.168.56.101", "hostname": None, "os": None}
    data = services_to_dict(services, target, generated_at="2026-11-19T10:00:00Z")

    assert data["schema_version"] == "1.0"
    assert data["generated_at"] == "2026-11-19T10:00:00Z"
    assert data["target"] == target
    assert data["unmatched"] == []
    assert len(data["services"]) == 1
    svc = data["services"][0]
    assert svc["port"] == 21
    assert svc["service"] == "ftp"
    assert svc["product"] == "vsftpd"
    assert svc["version"] == "2.3.4"
    assert svc["cpe"] == ["cpe:/a:vsftpd:vsftpd:2.3.4"]
    assert svc["extra_info"] == {"extrainfo": "..."}
    assert svc["source"].endswith(".xml")
