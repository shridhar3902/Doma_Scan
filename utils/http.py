"""HTTP helpers with session pooling, exponential backoff, UA rotation, and proxy support."""

from __future__ import annotations

import random
import time
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from utils.output import verbose_print

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 10
MAX_RETRIES = 3
BACKOFF_FACTOR = 1  # 1s -> 2s -> 4s exponential backoff

# Realistic User-Agent rotation pool
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------
_session: Optional[requests.Session] = None
_proxy_config: Optional[Dict[str, str]] = None
_rate_limit_delay: float = 0.0


def configure(
    proxy: Optional[str] = None,
    rate_limit: float = 0.0,
) -> None:
    """Configure global HTTP settings. Call once before scanning."""
    global _proxy_config, _rate_limit_delay
    if proxy:
        _proxy_config = {"http": proxy, "https": proxy}
    _rate_limit_delay = max(0.0, rate_limit)


def _get_session() -> requests.Session:
    """Return a shared session with connection pooling and retry adapter."""
    global _session
    if _session is None:
        _session = requests.Session()
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=20,
        )
        _session.mount("https://", adapter)
        _session.mount("http://", adapter)
        if _proxy_config:
            _session.proxies.update(_proxy_config)
    return _session


def _random_ua() -> str:
    """Pick a random realistic User-Agent string."""
    return random.choice(USER_AGENTS)


# ---------------------------------------------------------------------------
# Core request helpers
# ---------------------------------------------------------------------------
def _request(
    url: str,
    verbose: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    method: str = "GET",
) -> Optional[requests.Response]:
    """Execute an HTTP request with session pooling, backoff, and UA rotation."""
    session = _get_session()
    headers = {"User-Agent": _random_ua()}

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if _rate_limit_delay > 0:
                time.sleep(_rate_limit_delay)

            verbose_print(verbose, f"HTTP {method} attempt {attempt}: {url}")

            if method.upper() == "HEAD":
                response = session.head(url, headers=headers, timeout=timeout, allow_redirects=True)
            else:
                response = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)

            response.raise_for_status()
            return response

        except requests.RequestException as exc:
            verbose_print(verbose, f"Request attempt {attempt} failed for {url}: {exc}")
            if attempt < MAX_RETRIES:
                wait = BACKOFF_FACTOR * (2 ** (attempt - 1))
                verbose_print(verbose, f"Backing off {wait}s before retry...")
                time.sleep(wait)

    return None


def get_text(url: str, verbose: bool = False, timeout: int = DEFAULT_TIMEOUT) -> Optional[str]:
    """Fetch URL and return response body as text, or None on failure."""
    response = _request(url, verbose=verbose, timeout=timeout)
    return response.text if response is not None else None


def get_json(url: str, verbose: bool = False, timeout: int = DEFAULT_TIMEOUT) -> Optional[Any]:
    """Fetch URL and return parsed JSON, or None on failure."""
    response = _request(url, verbose=verbose, timeout=timeout)
    if response is None:
        return None
    try:
        return response.json()
    except ValueError:
        verbose_print(verbose, f"Invalid JSON payload from {url}")
        return None


def get_headers(url: str, verbose: bool = False, timeout: int = DEFAULT_TIMEOUT) -> Optional[Dict[str, str]]:
    """Fetch only HTTP headers via HEAD request, or None on failure."""
    response = _request(url, verbose=verbose, timeout=timeout, method="HEAD")
    if response is not None:
        return dict(response.headers)
    # Fallback to GET if HEAD is blocked
    response = _request(url, verbose=verbose, timeout=timeout, method="GET")
    return dict(response.headers) if response is not None else None
