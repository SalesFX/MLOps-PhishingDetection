from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from network_security.utils.feature_extractor.url_validator import (
    SSRFBlockedError,
    validate_url_for_fetch,
)

FETCH_TIMEOUT = 10.0  # seconds


@dataclass
class HTTPFetchResult:
    url: str
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    html: str = ""
    is_redirect: bool = False
    error: str | None = None
    soup: BeautifulSoup | None = None


async def fetch_url_safe(url: str, timeout: float = FETCH_TIMEOUT) -> HTTPFetchResult:
    """HTTP GET with SSRF validation, timeout and follow_redirects=False.

    Never raises — errors are returned as HTTPFetchResult with error populated.
    """
    try:
        validate_url_for_fetch(url)
    except SSRFBlockedError as e:
        return HTTPFetchResult(url=url, error=f"SSRF blocked: {e}")

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            response = await client.get(url)
            is_redirect = response.status_code in range(300, 400)
            html = response.text if not is_redirect else ""
            soup = BeautifulSoup(html, "html.parser") if html else None
            return HTTPFetchResult(
                url=url,
                status_code=response.status_code,
                headers=dict(response.headers),
                html=html,
                is_redirect=is_redirect,
                soup=soup,
            )
    except httpx.TimeoutException:
        return HTTPFetchResult(url=url, error="HTTP request timed out")
    except Exception as e:
        return HTTPFetchResult(url=url, error=f"HTTP fetch failed: {e}")


def _extract_domain(url: str) -> str:
    return urlparse(url).hostname or ""


def _is_external(href: str, base_domain: str) -> bool:
    """True if href points to a different domain than base_domain."""
    if not href:
        return False
    h = href.strip()
    if h.startswith("//"):
        h = "http:" + h
    if not h.startswith(("http://", "https://")):
        return False  # relative → same domain
    return _extract_domain(h) != base_domain


def _pct_to_feature(pct: float, low: float, high: float) -> int:
    """Converts percentage of external resources to UCI value: 1/0/-1."""
    if pct < low:
        return 1
    if pct <= high:
        return 0
    return -1


def feat_ssl_final_state(result: HTTPFetchResult) -> int:
    # 1 = HTTPS and request ok, -1 = HTTP, 0 = error/unknown
    if result.error:
        return 0
    if result.url.startswith("https://"):
        return 1 if result.status_code and result.status_code < 400 else 0
    return -1


def feat_request_url(result: HTTPFetchResult, base_domain: str) -> int:
    # % external resources (img, script, link[href], audio, video, source)
    # < 22% → 1, 22-61% → 0, > 61% → -1
    if not result.soup:
        return 0
    tags = result.soup.find_all(["img", "script", "audio", "video", "source"])
    links = result.soup.find_all("link", href=True)
    urls = [t.get("src", "") for t in tags] + [t["href"] for t in links]
    if not urls:
        return 1
    external = sum(1 for u in urls if _is_external(u, base_domain))
    pct = external / len(urls) * 100
    return _pct_to_feature(pct, 22.0, 61.0)


def feat_url_of_anchor(result: HTTPFetchResult, base_domain: str) -> int:
    # % anchors that are external/suspicious (#, javascript:, empty, different domain)
    # < 31% → 1, 31-67% → 0, > 67% → -1
    if not result.soup:
        return 0
    anchors = result.soup.find_all("a", href=True)
    if not anchors:
        return 1
    suspicious = 0
    for a in anchors:
        href = a["href"].strip()
        if not href or href == "#" or href.startswith("javascript:") or _is_external(href, base_domain):
            suspicious += 1
    pct = suspicious / len(anchors) * 100
    return _pct_to_feature(pct, 31.0, 67.0)


def feat_links_in_tags(result: HTTPFetchResult, base_domain: str) -> int:
    # % external links in <meta>, <script src>, <link href>
    # < 17% → 1, 17-81% → 0, > 81% → -1
    if not result.soup:
        return 0
    urls: list[str] = []
    for tag in result.soup.find_all("meta", content=True):
        c = tag.get("content", "")
        if c.startswith(("http://", "https://")):
            urls.append(c)
    for tag in result.soup.find_all("script", src=True):
        urls.append(tag["src"])
    for tag in result.soup.find_all("link", href=True):
        urls.append(tag["href"])
    if not urls:
        return 1
    external = sum(1 for u in urls if _is_external(u, base_domain))
    pct = external / len(urls) * 100
    return _pct_to_feature(pct, 17.0, 81.0)


def feat_sfh(result: HTTPFetchResult, base_domain: str) -> int:
    # Server Form Handler: action="" or about:blank → 0, external → -1, ok → 1
    if not result.soup:
        return 0
    forms = result.soup.find_all("form")
    if not forms:
        return 1
    for form in forms:
        action = (form.get("action") or "").strip()
        if not action or action.lower() == "about:blank":
            return 0
        if _is_external(action, base_domain):
            return -1
    return 1


def feat_submitting_to_email(result: HTTPFetchResult) -> int:
    # -1 if any form action starts with mailto:
    if not result.soup:
        return 1
    for form in result.soup.find_all("form"):
        action = (form.get("action") or "").strip().lower()
        if action.startswith("mailto:"):
            return -1
    return 1


def feat_redirect(result: HTTPFetchResult) -> int:
    # -1 if response was 3xx (redirect), 1 if not
    if result.error:
        return 0
    return -1 if result.is_redirect else 1


def feat_on_mouseover(result: HTTPFetchResult) -> int:
    # -1 if HTML contains onmouseover, 1 if not
    if not result.html:
        return 0
    return -1 if "onmouseover" in result.html.lower() else 1


def feat_right_click(result: HTTPFetchResult) -> int:
    # -1 if HTML blocks right-click (event.button==2, contextmenu, return false)
    if not result.html:
        return 0
    html_lower = result.html.lower()
    patterns = ["event.button==2", "contextmenu", "oncontextmenu"]
    return -1 if any(p in html_lower for p in patterns) else 1


def feat_popup_window(result: HTTPFetchResult) -> int:
    # -1 if HTML contains window.open (popups are suspicious)
    # NOTE: dataset uses typo "popUpWidnow" — feature name kept in features.py
    if not result.html:
        return 0
    return -1 if "window.open" in result.html.lower() else 1


def feat_iframe(result: HTTPFetchResult) -> int:
    # -1 if HTML contains <iframe> or <frame>, 1 if not
    if not result.soup:
        return 0
    return -1 if result.soup.find(["iframe", "frame"]) else 1


def feat_favicon(result: HTTPFetchResult, base_domain: str) -> int:
    # -1 if favicon comes from external domain, 1 if same domain or absent
    if not result.soup:
        return 1
    for link in result.soup.find_all("link"):
        rel = " ".join(link.get("rel", [])).lower()
        if "icon" in rel:
            href = link.get("href", "")
            if _is_external(href, base_domain):
                return -1
    return 1


_HTTP_FEATURE_NAMES: tuple[str, ...] = (
    "SSLfinal_State",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "Favicon",
)


async def extract_http_features(url: str) -> dict[str, object]:
    """Performs a single fetch and computes all 12 HTTP/HTML features.

    Returns {"features": dict[str, int], "warnings": list[str], "fetch_error": str | None}.
    """
    base_domain = _extract_domain(url)
    result = await fetch_url_safe(url)

    features: dict[str, int] = {}
    warnings: list[str] = []

    http_feature_funcs: dict[str, object] = {
        "SSLfinal_State":      lambda r: feat_ssl_final_state(r),
        "Request_URL":         lambda r: feat_request_url(r, base_domain),
        "URL_of_Anchor":       lambda r: feat_url_of_anchor(r, base_domain),
        "Links_in_tags":       lambda r: feat_links_in_tags(r, base_domain),
        "SFH":                 lambda r: feat_sfh(r, base_domain),
        "Submitting_to_email": lambda r: feat_submitting_to_email(r),
        "Redirect":            lambda r: feat_redirect(r),
        "on_mouseover":        lambda r: feat_on_mouseover(r),
        "RightClick":          lambda r: feat_right_click(r),
        "popUpWidnow":         lambda r: feat_popup_window(r),
        "Iframe":              lambda r: feat_iframe(r),
        "Favicon":             lambda r: feat_favicon(r, base_domain),
    }

    if result.error:
        for name in http_feature_funcs:
            features[name] = 0
            warnings.append(f"{name}: fallback neutro (fetch falhou: {result.error})")
    else:
        for name, func in http_feature_funcs.items():
            try:
                features[name] = func(result)  # type: ignore[operator]
                warnings.append(f"{name}: extraido via HTTP/HTML")
            except Exception as e:
                features[name] = 0
                warnings.append(f"{name}: fallback neutro (erro na extracao: {e})")

    return {"features": features, "warnings": warnings, "fetch_error": result.error}
