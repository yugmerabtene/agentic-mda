"""Tests unitaires de la validation de perimetre (scripts/recon/scope.py).

Aucun reseau n'est sollicite : seules les adresses IP sont analysees localement.
"""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.recon.scope import ScopeError, is_authorized, parse_target, validate_target  # noqa: E402


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
        "127.0.0.1",
        "127.255.255.255",
    ],
)
def test_private_and_loopback_addresses_are_authorized(ip: str) -> None:
    """Les adresses RFC1918 et loopback doivent etre autorisees."""
    assert is_authorized(parse_target(ip)) is True
    assert validate_target(ip) == parse_target(ip)


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "203.0.113.5",
        "198.51.100.23",
        "172.32.0.1",
        "192.169.0.1",
        "0.0.0.0",
        "255.255.255.255",
    ],
)
def test_public_and_out_of_scope_addresses_are_refused(ip: str) -> None:
    """Les adresses publiques et hors perimetre doivent etre refusees."""
    assert is_authorized(parse_target(ip)) is False
    with pytest.raises(ScopeError):
        validate_target(ip)


@pytest.mark.parametrize(
    "bad", ["not-an-ip", "192.168.56.999", "", "192.168.56", "999.999.999.999"]
)
def test_invalid_format_raises_scope_error(bad: str) -> None:
    """Une chaine qui n'est pas une adresse IPv4 leve ScopeError."""
    with pytest.raises(ScopeError):
        parse_target(bad)


def test_validate_target_returns_ipv4address() -> None:
    """validate_target retourne une adresse IPv4 normalisee."""
    result = validate_target("192.168.56.101")
    assert result == ipaddress.IPv4Address("192.168.56.101")
