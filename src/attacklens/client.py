"""HTTP client used by the CLI and the host agent to reach the API."""

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class ApiError(Exception):
    """The API refused a request or could not be reached."""


def api_post(api_url: str, path: str, payload: dict[str, Any], timeout: float = 30) -> Any:
    """Send a JSON request to the API and return its decoded answer."""
    headers = {"Content-Type": "application/json", "User-Agent": "AttackLens/0.1"}
    api_key = os.getenv("ATTACKLENS_API_KEY")
    if api_key:
        headers["X-API-Key"] = api_key
    request = Request(
        f"{api_url.rstrip('/')}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read()
    except HTTPError as error:
        raise ApiError(f"The API refused the request: HTTP {error.code}.") from error
    except (OSError, URLError) as error:
        raise ApiError(f"Unable to reach the API at {api_url}.") from error
    return json.loads(body) if body else None


def send_report(document: dict[str, Any], api_url: str) -> None:
    """Send a finished scan to the API that owns the database."""
    api_post(api_url, "/api/reports", document)
