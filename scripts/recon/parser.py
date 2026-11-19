"""Normalisation des sorties nmap XML vers l'inventaire de services.

Produit des enregistrements de services traçables vers la preuve brute
(source = fichier XML nmap) pour alimenter data/services.json.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class NmapService:
    """Service ouvert detecte par nmap sur un hote."""

    port: int
    protocol: str
    state: str
    service: str
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    cpe: list[str] = field(default_factory=list)
    source: str = ""


def parse_nmap_xml(xml_path: Path) -> list[NmapService]:
    """Parse un fichier XML nmap et retourne les services ouverts.

    Les ports non ouverts (fermes, filtres) sont ignores. Les hotes sans
    adresse IPv4 sont ignores.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    services: list[NmapService] = []
    for host in root.findall("host"):
        host_ip = _host_ipv4(host)
        if host_ip is None:
            continue

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            state = (
                state_elem.get("state", "unknown")
                if state_elem is not None
                else "unknown"
            )
            if state != "open":
                continue

            port_id = int(port_elem.get("portid", "0"))
            protocol = port_elem.get("protocol", "tcp")

            service_elem = port_elem.find("service")
            service_name = product = version = extrainfo = None
            cpe: list[str] = []
            if service_elem is not None:
                service_name = service_elem.get("name")
                product = service_elem.get("product")
                version = service_elem.get("version")
                extrainfo = service_elem.get("extrainfo")
                for cpe_elem in service_elem.findall("cpe"):
                    if cpe_elem.text:
                        cpe.append(cpe_elem.text.strip())

            services.append(
                NmapService(
                    port=port_id,
                    protocol=protocol,
                    state=state,
                    service=service_name or "unknown",
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                    cpe=cpe,
                    source=str(xml_path),
                )
            )

    return services


def _host_ipv4(host) -> str | None:
    """Retourne l'adresse IPv4 d'un hote nmap, ou None."""
    for address in host.findall("address"):
        if address.get("addrtype") == "ipv4":
            return address.get("addr")
    return None


def services_to_dict(
    services: list[NmapService],
    target: dict,
    generated_at: str | None = None,
) -> dict:
    """Construit le dictionnaire JSON normalise (schema data/services.json)."""
    from datetime import datetime, timezone

    if generated_at is None:
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "target": target,
        "services": [
            {
                "port": svc.port,
                "protocol": svc.protocol,
                "state": svc.state,
                "service": svc.service,
                "product": svc.product,
                "version": svc.version,
                "cpe": svc.cpe,
                "extra_info": {"extrainfo": svc.extrainfo} if svc.extrainfo else {},
                "source": svc.source,
            }
            for svc in services
        ],
        "unmatched": [],
    }
