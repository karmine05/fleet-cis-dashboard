"""Default HTTP transport. Tests inject a fake."""

from __future__ import annotations

from typing import Any, Mapping, Tuple

DEFAULT_TIMEOUT_SECONDS = 10
RESPONSE_SNIPPET = 500


def post_json(
    method: str,
    url: str,
    headers: Mapping[str, str],
    json_body: Mapping[str, Any],
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> Tuple[int, str]:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib.parse import urlparse, urlunparse
    from alerting.ssrf import UnsafeWebhookUrl, _ip_blocked, _literal_ips, default_resolver

    # Resolve once, vet every address, then connect to the vetted IP. Letting requests
    # resolve again would allow DNS rebinding past the private-address check.
    parsed = urlparse(url)
    host = parsed.hostname or ""
    addresses = _literal_ips(host) or default_resolver(host)
    if not addresses or any(_ip_blocked(a) for a in addresses):
        raise UnsafeWebhookUrl("webhook URL must not target a private or loopback address")
    ip = addresses[0]
    netloc = (f"[{ip}]" if ":" in ip else ip) + (f":{parsed.port}" if parsed.port else "")

    class _Pinned(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            kwargs["server_hostname"] = host  # SNI and certificate check use the real name
            kwargs["assert_hostname"] = host
            super().init_poolmanager(*args, **kwargs)

    with requests.Session() as session:
        session.mount("https://", _Pinned())
        with session.request(
            method,
            urlunparse(parsed._replace(netloc=netloc)),
            headers={**dict(headers), "Host": parsed.netloc.rsplit("@", 1)[-1]},
            json=dict(json_body),
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        ) as response:
            # One bounded read: response.text (or read(amt)) would wait out a trickling or huge body.
            body = response.raw.read1(RESPONSE_SNIPPET, decode_content=True) or b""
            status_code = response.status_code
    return status_code, body[:RESPONSE_SNIPPET].decode("utf-8", errors="replace")
