"""Reject non-http(s) and loopback/private webhook destinations."""

from __future__ import annotations

import ipaddress
import socket
from typing import Callable, List, Sequence
from urllib.parse import urlparse

Resolver = Callable[[str], Sequence[str]]

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata.google.internal",
    }
)


class UnsafeWebhookUrl(ValueError):
    """Operator-supplied URL is not safe to POST to."""


def validate_webhook_url(url: str, resolver: Resolver | None = None) -> str:
    """Return the stripped URL or raise UnsafeWebhookUrl."""
    raw = (url or "").strip()
    if not raw:
        raise UnsafeWebhookUrl("webhook URL is required")
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeWebhookUrl("webhook URL must be http or https")
    if parsed.username or parsed.password:
        raise UnsafeWebhookUrl("webhook URL must not include credentials")
    host = (parsed.hostname or "").strip().rstrip(".")
    if not host:
        raise UnsafeWebhookUrl("webhook URL host is missing")
    if host.lower() in _BLOCKED_HOSTNAMES:
        raise UnsafeWebhookUrl("webhook URL host is not allowed")
    if "/" in host or "\\" in host:
        raise UnsafeWebhookUrl("webhook URL host is not allowed")

    addresses = _literal_ips(host)
    if not addresses:
        resolve = resolver or default_resolver
        try:
            addresses = list(resolve(host))
        except OSError as exc:
            raise UnsafeWebhookUrl(f"webhook URL host could not be resolved: {exc}") from exc
        if not addresses:
            raise UnsafeWebhookUrl("webhook URL host could not be resolved")

    for addr in addresses:
        if _ip_blocked(addr):
            raise UnsafeWebhookUrl("webhook URL must not target a private or loopback address")
    return raw


def default_resolver(hostname: str) -> List[str]:
    results = socket.getaddrinfo(hostname, None)
    out = []
    seen = set()
    for item in results:
        sockaddr = item[4]
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _literal_ips(host: str) -> List[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        return []


def _ip_blocked(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    if ip.version == 6 and getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )
