"""Validation du perimetre de cible (adresses IP autorisees au lab).

Seules les adresses privees RFC 1918 (10/8, 172.16/12, 192.168/16) et
l'adresse de boucleback (127/8) sont autorisees. Toute adresse publique
est refusee.
"""

from __future__ import annotations

import ipaddress

# Reseaux prives RFC 1918 autorises dans le perimetre du lab.
PRIVATE_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Reseau de boucleback (loopback), autorise pour les tests locaux.
LOOPBACK_NETWORK: ipaddress.IPv4Network = ipaddress.ip_network("127.0.0.0/8")


class ScopeError(ValueError):
    """Levee quand une cible est invalide ou hors perimetre lab."""


def parse_target(target: str) -> ipaddress.IPv4Address:
    """Convertit une chaine en adresse IPv4.

    Leve ScopeError si la chaine n'est pas une adresse IPv4 valide.
    """
    try:
        return ipaddress.IPv4Address(target)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ScopeError(f"Adresse IP invalide : {target}") from exc


def is_authorized(ip: ipaddress.IPv4Address) -> bool:
    """Retourne True si l'adresse est privee RFC1918 ou loopback."""
    if ip in LOOPBACK_NETWORK:
        return True
    return any(ip in network for network in PRIVATE_NETWORKS)


def validate_target(target: str) -> ipaddress.IPv4Address:
    """Valide une cible de scan.

    Verifie le format de l'adresse puis l'appartenance au perimetre lab
    (RFC1918 ou loopback). Leve ScopeError dans le cas contraire.
    """
    ip = parse_target(target)
    if not is_authorized(ip):
        raise ScopeError(
            f"Cible refusee hors perimetre lab (non RFC1918, non loopback) : {ip}"
        )
    return ip
