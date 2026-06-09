"""Tests for network_security/utils/feature_extractor/dns_whois_features.py"""
import asyncio
import socket
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from network_security.utils.feature_extractor.dns_whois_features import (
    _normalize_date,
    extract_dns_whois_features,
    feat_age_of_domain,
    feat_dns_record,
    feat_domain_registration_length,
)
from network_security.utils.feature_extractor.url_validator import SSRFBlockedError

PUBLIC_ADDR = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


def make_whois_mock(
    creation_date: object = None,
    expiration_date: object = None,
) -> MagicMock:
    w = MagicMock()
    w.get.side_effect = lambda key: {
        "creation_date": creation_date,
        "expiration_date": expiration_date,
    }.get(key)
    return w


# ---------------------------------------------------------------------------
# DNSRecord
# ---------------------------------------------------------------------------


@patch(
    "network_security.utils.feature_extractor.dns_whois_features.socket.getaddrinfo",
    return_value=PUBLIC_ADDR,
)
def test_dns_record_resolves_correctly(mock_dns: MagicMock) -> None:
    result = feat_dns_record("example.com")
    assert result == 1


@patch(
    "network_security.utils.feature_extractor.dns_whois_features.socket.getaddrinfo",
    side_effect=socket.gaierror("Name or service not known"),
)
def test_dns_record_fails_returns_minus_one(mock_dns: MagicMock) -> None:
    result = feat_dns_record("nonexistent-domain-xyz.invalid")
    assert result == -1


# ---------------------------------------------------------------------------
# age_of_domain
# ---------------------------------------------------------------------------


def test_age_of_domain_old_domain_returns_one() -> None:
    creation = datetime.now(tz=timezone.utc) - timedelta(days=400)
    w = make_whois_mock(creation_date=creation)
    assert feat_age_of_domain(w) == 1


def test_age_of_domain_recent_domain_returns_minus_one() -> None:
    creation = datetime.now(tz=timezone.utc) - timedelta(days=30)
    w = make_whois_mock(creation_date=creation)
    assert feat_age_of_domain(w) == -1


def test_age_of_domain_creation_as_list() -> None:
    now = datetime.now(tz=timezone.utc)
    dates = [now - timedelta(days=400), now - timedelta(days=200)]
    w = make_whois_mock(creation_date=dates)
    # _normalize_date picks the first element — 400 days ago → old → 1
    assert feat_age_of_domain(w) == 1


def test_age_of_domain_no_creation_date_returns_zero() -> None:
    w = make_whois_mock(creation_date=None)
    assert feat_age_of_domain(w) == 0


# ---------------------------------------------------------------------------
# Domain_registeration_length
# ---------------------------------------------------------------------------


def test_registration_length_long_returns_one() -> None:
    expiration = datetime.now(tz=timezone.utc) + timedelta(days=400)
    w = make_whois_mock(expiration_date=expiration)
    assert feat_domain_registration_length(w) == 1


def test_registration_length_short_returns_minus_one() -> None:
    expiration = datetime.now(tz=timezone.utc) + timedelta(days=30)
    w = make_whois_mock(expiration_date=expiration)
    assert feat_domain_registration_length(w) == -1


def test_registration_length_as_list() -> None:
    now = datetime.now(tz=timezone.utc)
    dates = [now + timedelta(days=400), now + timedelta(days=100)]
    w = make_whois_mock(expiration_date=dates)
    # _normalize_date picks the first element — 400 days in future → 1
    assert feat_domain_registration_length(w) == 1


def test_registration_length_no_expiration_returns_zero() -> None:
    w = make_whois_mock(expiration_date=None)
    assert feat_domain_registration_length(w) == 0


# ---------------------------------------------------------------------------
# IP direct URL skips WHOIS
# ---------------------------------------------------------------------------


@patch("network_security.utils.feature_extractor.dns_whois_features.whois.whois")
def test_ip_direct_url_skips_whois(mock_whois: MagicMock) -> None:
    result = asyncio.run(extract_dns_whois_features("http://93.184.216.34/path"))
    mock_whois.assert_not_called()
    assert result["features"]["age_of_domain"] == 0
    assert result["features"]["Domain_registeration_length"] == 0


# ---------------------------------------------------------------------------
# Private IP blocked — DNS not consulted
# ---------------------------------------------------------------------------


@patch(
    "network_security.utils.feature_extractor.dns_whois_features.socket.getaddrinfo",
)
def test_private_ip_hostname_dns_returns_zero(mock_dns: MagicMock) -> None:
    result = feat_dns_record("192.168.1.1")
    mock_dns.assert_not_called()
    assert result == 0


# ---------------------------------------------------------------------------
# extract_dns_whois_features returns 3 features
# ---------------------------------------------------------------------------


@patch("network_security.utils.feature_extractor.dns_whois_features.whois.whois")
@patch(
    "network_security.utils.feature_extractor.dns_whois_features.socket.getaddrinfo",
    return_value=PUBLIC_ADDR,
)
def test_extract_returns_3_dns_whois_features(
    mock_dns: MagicMock, mock_whois: MagicMock
) -> None:
    now = datetime.now(tz=timezone.utc)
    w = make_whois_mock(
        creation_date=now - timedelta(days=400),
        expiration_date=now + timedelta(days=400),
    )
    mock_whois.return_value = w

    result = asyncio.run(extract_dns_whois_features("https://example.com"))
    assert set(result["features"].keys()) == {"DNSRecord", "age_of_domain", "Domain_registeration_length"}
    assert len(result["features"]) == 3
    assert result["features"]["DNSRecord"] == 1
    assert result["features"]["age_of_domain"] == 1
    assert result["features"]["Domain_registeration_length"] == 1


# ---------------------------------------------------------------------------
# Integration: URLFeatureExtractor returns 30 features with DNS/WHOIS mocked
# ---------------------------------------------------------------------------


@patch("network_security.utils.feature_extractor.dns_whois_features.whois.whois")
@patch(
    "network_security.utils.feature_extractor.dns_whois_features.socket.getaddrinfo",
    return_value=PUBLIC_ADDR,
)
def test_extract_returns_30_features(
    mock_dns: MagicMock, mock_whois: MagicMock
) -> None:
    import httpx
    import respx

    from network_security.utils.feature_extractor.extractor import URLFeatureExtractor
    from network_security.utils.feature_extractor.features import FEATURE_ORDER

    now = datetime.now(tz=timezone.utc)
    w = make_whois_mock(
        creation_date=now - timedelta(days=400),
        expiration_date=now + timedelta(days=400),
    )
    mock_whois.return_value = w

    with respx.mock:
        respx.get("https://example.com").mock(
            return_value=httpx.Response(200, text="<html><body><p>hi</p></body></html>")
        )
        extractor = URLFeatureExtractor()
        result = asyncio.run(extractor.extract("https://example.com"))

    assert len(result["features"]) == 30
    for feat in FEATURE_ORDER:
        assert feat in result["features"]


# ---------------------------------------------------------------------------
# API features remain fallback 0 after DNS/WHOIS are implemented
# ---------------------------------------------------------------------------


@patch("network_security.utils.feature_extractor.dns_whois_features.whois.whois")
@patch(
    "network_security.utils.feature_extractor.dns_whois_features.socket.getaddrinfo",
    return_value=PUBLIC_ADDR,
)
def test_api_features_still_fallback_after_dns_whois(
    mock_dns: MagicMock, mock_whois: MagicMock
) -> None:
    import httpx
    import respx

    from network_security.utils.feature_extractor.extractor import URLFeatureExtractor

    now = datetime.now(tz=timezone.utc)
    w = make_whois_mock(
        creation_date=now - timedelta(days=400),
        expiration_date=now + timedelta(days=400),
    )
    mock_whois.return_value = w

    with respx.mock:
        respx.get("https://example.com").mock(
            return_value=httpx.Response(200, text="<html><body></body></html>")
        )
        extractor = URLFeatureExtractor()
        result = asyncio.run(extractor.extract("https://example.com"))

    features = result["features"]
    for feat in ("web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page", "Statistical_report"):
        assert features[feat] == 0, f"{feat} should still be fallback 0"


# ---------------------------------------------------------------------------
# Extraction status: SSRF-blocked HTTP + successful DNS/WHOIS = 13 calculated
# ---------------------------------------------------------------------------


@patch("network_security.utils.feature_extractor.dns_whois_features.whois.whois")
@patch(
    "network_security.utils.feature_extractor.dns_whois_features.socket.getaddrinfo",
    return_value=PUBLIC_ADDR,
)
@patch(
    "network_security.utils.feature_extractor.http_features.validate_url_for_fetch",
    side_effect=SSRFBlockedError("blocked for test"),
)
def test_extraction_status_incremental_dns_whois_adds_3(
    mock_validate: MagicMock,
    mock_dns: MagicMock,
    mock_whois: MagicMock,
) -> None:
    """With HTTP SSRF-blocked (0 HTTP features) and DNS/WHOIS succeeding:
    10 string + 3 DNS/WHOIS = 13 calculated, 17 fallback."""
    from network_security.utils.feature_extractor.extractor import URLFeatureExtractor

    now = datetime.now(tz=timezone.utc)
    w = make_whois_mock(
        creation_date=now - timedelta(days=400),
        expiration_date=now + timedelta(days=400),
    )
    mock_whois.return_value = w

    extractor = URLFeatureExtractor()
    result = asyncio.run(extractor.extract("https://example.com"))

    warnings = result["warnings"]
    fallback_count = sum(1 for w_msg in warnings if "fallback" in w_msg)
    calculated_count = 30 - fallback_count

    # 10 string + 3 DNS/WHOIS = 13 calculated; 12 HTTP + 5 external-API = 17 fallback
    assert calculated_count == 13
    assert fallback_count == 17
