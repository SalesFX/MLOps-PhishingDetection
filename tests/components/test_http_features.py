"""Tests for network_security/utils/feature_extractor/http_features.py"""
import asyncio
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from network_security.utils.feature_extractor.http_features import (
    HTTPFetchResult,
    extract_http_features,
    feat_favicon,
    feat_iframe,
    feat_links_in_tags,
    feat_on_mouseover,
    feat_popup_window,
    feat_redirect,
    feat_request_url,
    feat_right_click,
    feat_sfh,
    feat_ssl_final_state,
    feat_submitting_to_email,
    feat_url_of_anchor,
    fetch_url_safe,
)


def make_result(
    html: str,
    url: str = "https://example.com",
    status: int = 200,
    is_redirect: bool = False,
) -> HTTPFetchResult:
    soup = BeautifulSoup(html, "html.parser") if html else None
    return HTTPFetchResult(
        url=url,
        status_code=status,
        html=html,
        soup=soup,
        is_redirect=is_redirect,
    )


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

@respx.mock
def test_ssrf_blocked_url_returns_fallback_not_request() -> None:
    """127.0.0.1 must be SSRF-blocked before any HTTP request is made."""
    result = asyncio.run(fetch_url_safe("http://127.0.0.1/admin"))
    # No HTTP request must have been sent; respx raises on unexpected requests
    assert result.error is not None
    assert "SSRF blocked" in result.error
    assert respx.calls.call_count == 0


# ---------------------------------------------------------------------------
# Iframe
# ---------------------------------------------------------------------------

def test_iframe_tag_detected() -> None:
    result = make_result('<html><body><iframe src="http://evil.com"></iframe></body></html>')
    assert feat_iframe(result) == -1


def test_frame_tag_detected() -> None:
    result = make_result('<html><frameset><frame src="http://evil.com"></frameset></html>')
    assert feat_iframe(result) == -1


def test_no_iframe_returns_one() -> None:
    result = make_result("<html><body><p>No frames here</p></body></html>")
    assert feat_iframe(result) == 1


# ---------------------------------------------------------------------------
# popUpWidnow
# ---------------------------------------------------------------------------

def test_window_open_detected() -> None:
    result = make_result('<html><body><script>window.open("http://evil.com")</script></body></html>')
    assert feat_popup_window(result) == -1


def test_no_popup_returns_one() -> None:
    result = make_result("<html><body><p>Clean page</p></body></html>")
    assert feat_popup_window(result) == 1


# ---------------------------------------------------------------------------
# on_mouseover
# ---------------------------------------------------------------------------

def test_onmouseover_detected() -> None:
    result = make_result('<html><body><a href="#" onmouseover="window.status=\'fake\'">link</a></body></html>')
    assert feat_on_mouseover(result) == -1


# ---------------------------------------------------------------------------
# RightClick
# ---------------------------------------------------------------------------

def test_right_click_blocked_contextmenu() -> None:
    result = make_result('<html><body oncontextmenu="return false;">content</body></html>')
    assert feat_right_click(result) == -1


# ---------------------------------------------------------------------------
# Submitting_to_email
# ---------------------------------------------------------------------------

def test_form_mailto_submitting_to_email() -> None:
    result = make_result('<html><body><form action="mailto:x@y.com"></form></body></html>')
    assert feat_submitting_to_email(result) == -1


# ---------------------------------------------------------------------------
# SFH
# ---------------------------------------------------------------------------

def test_form_external_action_sfh() -> None:
    result = make_result(
        '<html><body><form action="http://evil.com/steal"></form></body></html>',
        url="https://example.com",
    )
    assert feat_sfh(result, "example.com") == -1


def test_form_empty_action_sfh() -> None:
    result = make_result('<html><body><form action=""></form></body></html>')
    assert feat_sfh(result, "example.com") == 0


def test_form_blank_action_sfh() -> None:
    result = make_result('<html><body><form action="about:blank"></form></body></html>')
    assert feat_sfh(result, "example.com") == 0


# ---------------------------------------------------------------------------
# URL_of_Anchor
# ---------------------------------------------------------------------------

def test_anchors_mostly_external() -> None:
    html = (
        '<html><body>'
        '<a href="http://evil1.com">1</a>'
        '<a href="http://evil2.com">2</a>'
        '<a href="http://evil3.com">3</a>'
        '<a href="http://evil4.com">4</a>'
        '<a href="http://evil5.com">5</a>'
        '</body></html>'
    )
    result = make_result(html, url="https://example.com")
    # 5 of 5 external = 100% > 67% → -1
    assert feat_url_of_anchor(result, "example.com") == -1


def test_anchors_all_internal() -> None:
    html = (
        '<html><body>'
        '<a href="/page1">1</a>'
        '<a href="/page2">2</a>'
        '<a href="/page3">3</a>'
        '<a href="/page4">4</a>'
        '<a href="/page5">5</a>'
        '</body></html>'
    )
    result = make_result(html, url="https://example.com")
    # 0 of 5 external = 0% < 31% → 1
    assert feat_url_of_anchor(result, "example.com") == 1


# ---------------------------------------------------------------------------
# Request_URL
# ---------------------------------------------------------------------------

def test_external_img_resources() -> None:
    html = (
        '<html><body>'
        '<img src="http://cdn1.evil.com/img.png">'
        '<img src="http://cdn2.evil.com/img.png">'
        '<img src="http://cdn3.evil.com/img.png">'
        '<img src="http://cdn4.evil.com/img.png">'
        '</body></html>'
    )
    result = make_result(html, url="https://example.com")
    # 4 of 4 external = 100% > 61% → -1
    assert feat_request_url(result, "example.com") == -1


def test_internal_resources() -> None:
    html = (
        '<html><body>'
        '<img src="/img1.png">'
        '<img src="/img2.png">'
        '<script src="/js/app.js"></script>'
        '</body></html>'
    )
    result = make_result(html, url="https://example.com")
    # 0 of 3 external = 0% < 22% → 1
    assert feat_request_url(result, "example.com") == 1


# ---------------------------------------------------------------------------
# Links_in_tags
# ---------------------------------------------------------------------------

def test_links_in_tags_external() -> None:
    # All 5 scripts are from an external domain → 100% > 81% → -1
    scripts = "".join(
        f'<script src="http://external.com/s{i}.js"></script>' for i in range(5)
    )
    html = f"<html><head>{scripts}</head><body></body></html>"
    result = make_result(html, url="https://example.com")
    assert feat_links_in_tags(result, "example.com") == -1


# ---------------------------------------------------------------------------
# Favicon
# ---------------------------------------------------------------------------

def test_external_favicon() -> None:
    html = '<html><head><link rel="icon" href="http://external.com/fav.ico"></head><body></body></html>'
    result = make_result(html, url="https://example.com")
    assert feat_favicon(result, "example.com") == -1


# ---------------------------------------------------------------------------
# Redirect
# ---------------------------------------------------------------------------

def test_redirect_3xx() -> None:
    result = HTTPFetchResult(url="http://example.com", status_code=302, is_redirect=True)
    assert feat_redirect(result) == -1


def test_no_redirect_200() -> None:
    result = make_result("<html><body>ok</body></html>", status=200)
    assert feat_redirect(result) == 1


# ---------------------------------------------------------------------------
# Timeout / error fallback
# ---------------------------------------------------------------------------

@respx.mock
def test_http_timeout_generates_fallback() -> None:
    """Timeout must make all 12 HTTP features fall back to 0."""
    respx.get("https://example.com").mock(side_effect=httpx.TimeoutException("timed out"))
    result = asyncio.run(extract_http_features("https://example.com"))
    for feat in ("SSLfinal_State", "Iframe", "popUpWidnow", "Redirect"):
        assert result["features"][feat] == 0, f"{feat} should be 0 on timeout"
    # Every warning for an HTTP feature must mention "fallback"
    for w in result["warnings"]:
        assert "fallback" in w, f"Expected 'fallback' in warning: {w!r}"


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------

def test_invalid_html_does_not_crash() -> None:
    """Malformed HTML must not raise — BeautifulSoup should handle it gracefully."""
    html = "<html><body<<iframe>>"
    result = make_result(html)
    # If the parser still finds an iframe-like tag in the malformed soup, -1 is
    # acceptable.  What must NOT happen is an exception.
    value = feat_iframe(result)
    assert value in (-1, 1, 0)


# ---------------------------------------------------------------------------
# Integration with URLFeatureExtractor via /predict-url
# ---------------------------------------------------------------------------

@respx.mock
@patch("app.NetworkModel")
@patch("app.load_object")
def test_extract_still_returns_30_features(
    mock_load_object: MagicMock,
    mock_network_model_cls: MagicMock,
) -> None:
    """With a mocked HTTP response, extract() must return exactly 30 features."""
    import numpy as np
    from app import app

    mock_load_object.side_effect = [MagicMock(), MagicMock()]
    instance = MagicMock()
    instance.predict.return_value = np.array([1])
    instance.predict_proba.return_value = np.array([[0.02, 0.98]])
    mock_network_model_cls.return_value = instance

    respx.get("https://example.com").mock(
        return_value=httpx.Response(200, text="<html><body><p>hello</p></body></html>")
    )

    tc = TestClient(app)
    response = tc.post("/predict-url", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert len(response.json()["features"]) == 30


@respx.mock
@patch("app.NetworkModel")
@patch("app.load_object")
def test_whois_dns_features_still_fallback(
    mock_load_object: MagicMock,
    mock_network_model_cls: MagicMock,
) -> None:
    """WHOIS/DNS features must still be 0 (not yet implemented)."""
    import numpy as np
    from app import app

    mock_load_object.side_effect = [MagicMock(), MagicMock()]
    instance = MagicMock()
    instance.predict.return_value = np.array([1])
    instance.predict_proba.return_value = np.array([[0.02, 0.98]])
    mock_network_model_cls.return_value = instance

    respx.get("https://example.com").mock(
        return_value=httpx.Response(200, text="<html><body></body></html>")
    )

    tc = TestClient(app)
    response = tc.post("/predict-url", json={"url": "https://example.com"})
    assert response.status_code == 200
    features = response.json()["features"]
    for feat in ("age_of_domain", "DNSRecord", "web_traffic", "Page_Rank"):
        assert features[feat] == 0, f"{feat} should still be fallback 0"


@respx.mock
@patch("app.NetworkModel")
@patch("app.load_object")
def test_extraction_status_shows_22_calculated(
    mock_load_object: MagicMock,
    mock_network_model_cls: MagicMock,
) -> None:
    """With a successful HTTP fetch, extraction_status.calculated_features must be 22."""
    import numpy as np
    from app import app

    mock_load_object.side_effect = [MagicMock(), MagicMock()]
    instance = MagicMock()
    instance.predict.return_value = np.array([1])
    instance.predict_proba.return_value = np.array([[0.02, 0.98]])
    mock_network_model_cls.return_value = instance

    respx.get("https://example.com").mock(
        return_value=httpx.Response(200, text="<html><body><p>hello</p></body></html>")
    )

    tc = TestClient(app)
    response = tc.post("/predict-url", json={"url": "https://example.com"})
    assert response.status_code == 200
    status = response.json()["extraction_status"]
    assert status["calculated_features"] == 22
    assert status["fallback_features"] == 8
