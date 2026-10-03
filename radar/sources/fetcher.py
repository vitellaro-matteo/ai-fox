"""Polite HTTP access with snapshots.

Live mode: every response is written to the snapshot folder before it is used.
Offline mode: the same files are read back and no request is made.
Both modes therefore run exactly the same parsing and storing code, which is
what makes `demo-offline` trustworthy.
"""

import json
import logging
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

log = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "Schwachstellen-Radar/0.1 (+contact: not-configured)"
TIMEOUT_SECONDS = 60
MAX_ATTEMPTS = 4
# Minimum pause between two requests to the same host. These are free public
# services; we would rather be slow than be a nuisance.
MIN_PAUSE_SECONDS = 0.5


class FetchError(Exception):
    pass


class Fetcher:
    def __init__(self, snapshot_dir: Path, offline: bool = False):
        self.snapshot_dir = Path(snapshot_dir)
        self.offline = offline
        self.requests_made = 0
        self._last_request_at: dict[str, float] = {}
        self._client = httpx.Client(
            headers={"User-Agent": os.environ.get("HTTP_USER_AGENT", DEFAULT_USER_AGENT)},
            timeout=TIMEOUT_SECONDS,
            follow_redirects=True,
        )

    def get_json(self, url: str, save_as: str):
        """Returns the parsed JSON for `url`, or None if it is not available.

        `save_as` is the file path inside the snapshot folder.
        """
        path = self.snapshot_dir / save_as
        if self.offline:
            if not path.exists():
                return None
            return json.loads(path.read_text(encoding="utf-8"))

        body = self.get_bytes(url)
        if body is None:
            return None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return json.loads(body)

    def get_bytes(self, url: str, extra_headers: dict | None = None) -> bytes | None:
        """GET with retries. Returns None when there is nothing to read:
        404, 204 (EUVD answers 204 for an unknown CVE), or 304 after a conditional request."""
        response = self.get_response(url, extra_headers)
        if response.status_code in (204, 304, 404):
            return None
        return response.content

    def get_response(self, url: str, extra_headers: dict | None = None) -> httpx.Response:
        host = urlsplit(url).netloc
        last_problem = ""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self._pause_for(host)
            try:
                response = self._client.get(url, headers=extra_headers)
            except httpx.HTTPError as error:
                last_problem = repr(error)
            else:
                self.requests_made += 1
                if response.status_code in (200, 204, 304, 404):
                    return response
                last_problem = f"HTTP {response.status_code}"
                # 4xx other than 429 will not get better by asking again.
                if response.status_code < 500 and response.status_code != 429:
                    break
            if attempt < MAX_ATTEMPTS:
                wait = 2**attempt  # 2, 4, 8 seconds
                log.warning("GET %s failed (%s), retry in %ss", url, last_problem, wait)
                time.sleep(wait)
        raise FetchError(f"GET {url} failed: {last_problem}")

    def _pause_for(self, host: str) -> None:
        elapsed = time.monotonic() - self._last_request_at.get(host, 0.0)
        if elapsed < MIN_PAUSE_SECONDS:
            time.sleep(MIN_PAUSE_SECONDS - elapsed)
        self._last_request_at[host] = time.monotonic()

    def close(self) -> None:
        self._client.close()
