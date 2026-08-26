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

    response = requests.request(
        method,
        url,
        headers=dict(headers),
        json=dict(json_body),
        timeout=timeout,
        allow_redirects=False,
    )
    text = response.text or ""
    return response.status_code, text[:RESPONSE_SNIPPET]
