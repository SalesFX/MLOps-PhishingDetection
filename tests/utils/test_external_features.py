import asyncio
import os

import httpx
import pytest
import respx
from unittest.mock import patch

from network_security.utils.feature_extractor.external_features import (
    extract_external_features,
    feat_google_index,
    feat_links_pointing_to_page,
    feat_page_rank,
    feat_statistical_report,
    feat_web_traffic,
)

# ---------------------------------------------------------------------------
# feat_statistical_report
# ---------------------------------------------------------------------------


@respx.mock
def test_statistical_report_threat_found() -> None:
    respx.post(url__startswith="https://safebrowsing.googleapis.com").mock(
        return_value=httpx.Response(
            200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
        )
    )
    with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "test-key"}):
        val, warn = asyncio.run(feat_statistical_report("https://example.com"))

    assert val == -1
    assert "ameaca detectada" in warn


@respx.mock
def test_statistical_report_no_threat() -> None:
    respx.post(url__startswith="https://safebrowsing.googleapis.com").mock(
        return_value=httpx.Response(200, json={})
    )
    with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "test-key"}):
        val, warn = asyncio.run(feat_statistical_report("https://example.com"))

    assert val == 1
    assert "URL limpa" in warn


def test_statistical_report_no_api_key() -> None:
    env_without_key = {
        k: v for k, v in os.environ.items() if k != "GOOGLE_SAFE_BROWSING_API_KEY"
    }
    with patch.dict(os.environ, env_without_key, clear=True):
        val, warn = asyncio.run(feat_statistical_report("https://example.com"))

    assert val == 0
    assert "nao configurada" in warn


@respx.mock
def test_statistical_report_timeout() -> None:
    respx.post(url__startswith="https://safebrowsing.googleapis.com").mock(
        side_effect=httpx.TimeoutException("timeout")
    )
    with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "test-key"}):
        val, warn = asyncio.run(feat_statistical_report("https://example.com"))

    assert val == 0
    assert "timeout" in warn


def test_statistical_report_ssrf_blocked_url() -> None:
    # IP privado — deve retornar fallback sem chamar a API.
    # respx.mock nao e necessario aqui porque nenhuma chamada HTTP deve ocorrer.
    with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "test-key"}):
        val, warn = asyncio.run(feat_statistical_report("http://127.0.0.1/"))

    assert val == 0
    assert "bloqueado" in warn


# ---------------------------------------------------------------------------
# feat_web_traffic
# ---------------------------------------------------------------------------


@respx.mock
def test_web_traffic_top_ranked() -> None:
    respx.get(url__startswith="https://tranco-list.eu").mock(
        return_value=httpx.Response(
            200, json={"ranks": [{"rank": 1000}], "domain": "example.com"}
        )
    )
    val, warn = asyncio.run(feat_web_traffic("https://example.com"))

    assert val == 1
    assert "rank popular" in warn


@respx.mock
def test_web_traffic_mid_ranked() -> None:
    respx.get(url__startswith="https://tranco-list.eu").mock(
        return_value=httpx.Response(
            200, json={"ranks": [{"rank": 200_000}], "domain": "example.com"}
        )
    )
    val, warn = asyncio.run(feat_web_traffic("https://example.com"))

    assert val == 0
    assert "rank medio" in warn


@respx.mock
def test_web_traffic_low_ranked() -> None:
    respx.get(url__startswith="https://tranco-list.eu").mock(
        return_value=httpx.Response(
            200, json={"ranks": [{"rank": 600_000}], "domain": "example.com"}
        )
    )
    val, warn = asyncio.run(feat_web_traffic("https://example.com"))

    assert val == -1
    assert "rank baixo" in warn


@respx.mock
def test_web_traffic_not_in_tranco() -> None:
    respx.get(url__startswith="https://tranco-list.eu").mock(
        return_value=httpx.Response(
            200, json={"ranks": [], "domain": "unknown.example"}
        )
    )
    val, warn = asyncio.run(feat_web_traffic("https://unknown.example"))

    assert val == 0
    assert "nao encontrado" in warn


@respx.mock
def test_web_traffic_timeout() -> None:
    respx.get(url__startswith="https://tranco-list.eu").mock(
        side_effect=httpx.TimeoutException("timeout")
    )
    val, warn = asyncio.run(feat_web_traffic("https://example.com"))

    assert val == 0
    assert "timeout" in warn


# ---------------------------------------------------------------------------
# fallback-only features
# ---------------------------------------------------------------------------


def test_page_rank_is_documented_fallback() -> None:
    val, warn = feat_page_rank()
    assert val == 0
    assert "PageRank obsoleto" in warn


def test_google_index_is_documented_fallback() -> None:
    val, warn = feat_google_index()
    assert val == 0
    assert "sem API gratuita" in warn


def test_links_pointing_is_documented_fallback() -> None:
    val, warn = feat_links_pointing_to_page()
    assert val == 0
    assert "API de backlinks" in warn


# ---------------------------------------------------------------------------
# extract_external_features integration
# ---------------------------------------------------------------------------


@respx.mock
def test_extract_external_features_returns_all_5() -> None:
    respx.get(url__startswith="https://tranco-list.eu").mock(
        return_value=httpx.Response(
            200, json={"ranks": [{"rank": 1000}], "domain": "example.com"}
        )
    )
    with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "test-key"}):
        respx.post(url__startswith="https://safebrowsing.googleapis.com").mock(
            return_value=httpx.Response(200, json={})
        )
        result = asyncio.run(extract_external_features("https://example.com"))

    assert set(result["features"].keys()) == {
        "web_traffic",
        "Statistical_report",
        "Page_Rank",
        "Google_Index",
        "Links_pointing_to_page",
    }
