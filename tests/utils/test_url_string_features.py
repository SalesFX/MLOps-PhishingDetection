"""Tests for the 10 URL-string features implemented in Etapa 2."""

import asyncio

import pytest

from network_security.utils.feature_extractor.extractor import URLFeatureExtractor
from network_security.utils.feature_extractor.features import FEATURE_ORDER


# ---------------------------------------------------------------------------
# having_IP_Address
# ---------------------------------------------------------------------------

class TestHavingIPAddress:
    def setup_method(self) -> None:
        self.extractor = URLFeatureExtractor()

    def test_ipv4_returns_minus_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://192.168.0.1/login"))
        assert result["features"]["having_IP_Address"] == -1

    def test_domain_returns_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://google.com"))
        assert result["features"]["having_IP_Address"] == 1

    def test_ipv6_returns_minus_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://[::1]/path"))
        assert result["features"]["having_IP_Address"] == -1


# ---------------------------------------------------------------------------
# URL_Length
# ---------------------------------------------------------------------------

class TestURLLength:
    def setup_method(self) -> None:
        self.extractor = URLFeatureExtractor()

    def test_short_url_returns_one(self) -> None:
        # 30-char URL -> legitimate
        url = "http://example.com/short"
        assert len(url) < 54
        result = asyncio.run(self.extractor.extract(url))
        assert result["features"]["URL_Length"] == 1

    def test_medium_url_returns_zero(self) -> None:
        # 60-char URL -> suspicious
        url = "http://example.com/" + "a" * 41  # 19 + 41 = 60
        assert 54 <= len(url) <= 75
        result = asyncio.run(self.extractor.extract(url))
        assert result["features"]["URL_Length"] == 0

    def test_long_url_returns_minus_one(self) -> None:
        # 80-char URL -> phishing
        url = "http://example.com/" + "a" * 61  # 19 + 61 = 80
        assert len(url) > 75
        result = asyncio.run(self.extractor.extract(url))
        assert result["features"]["URL_Length"] == -1


# ---------------------------------------------------------------------------
# Shortining_Service
# ---------------------------------------------------------------------------

class TestShorteningService:
    def setup_method(self) -> None:
        self.extractor = URLFeatureExtractor()

    def test_known_shortener_returns_minus_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://bit.ly/abc123"))
        assert result["features"]["Shortining_Service"] == -1

    def test_regular_domain_returns_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://google.com/some/path"))
        assert result["features"]["Shortining_Service"] == 1


# ---------------------------------------------------------------------------
# having_At_Symbol
# ---------------------------------------------------------------------------

class TestHavingAtSymbol:
    def setup_method(self) -> None:
        self.extractor = URLFeatureExtractor()

    def test_at_in_url_returns_minus_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://user@evil.com"))
        assert result["features"]["having_At_Symbol"] == -1

    def test_no_at_returns_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://example.com"))
        assert result["features"]["having_At_Symbol"] == 1

    def test_fake_domain_in_credentials_returns_minus_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://example.com@evil.com/path"))
        assert result["features"]["having_At_Symbol"] == -1


# ---------------------------------------------------------------------------
# double_slash_redirecting
# ---------------------------------------------------------------------------

class TestDoubleSlashRedirecting:
    def setup_method(self) -> None:
        self.extractor = URLFeatureExtractor()

    def test_normal_url_returns_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://example.com"))
        assert result["features"]["double_slash_redirecting"] == 1

    def test_double_slash_in_path_returns_minus_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://example.com//redirect"))
        assert result["features"]["double_slash_redirecting"] == -1


# ---------------------------------------------------------------------------
# Prefix_Suffix
# ---------------------------------------------------------------------------

class TestPrefixSuffix:
    def setup_method(self) -> None:
        self.extractor = URLFeatureExtractor()

    def test_hyphen_in_domain_returns_minus_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://secure-login-example.com"))
        assert result["features"]["Prefix_Suffix"] == -1

    def test_no_hyphen_returns_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://google.com"))
        assert result["features"]["Prefix_Suffix"] == 1


# ---------------------------------------------------------------------------
# having_Sub_Domain
# ---------------------------------------------------------------------------

class TestHavingSubDomain:
    def setup_method(self) -> None:
        self.extractor = URLFeatureExtractor()

    def test_one_dot_returns_one(self) -> None:
        # google.com -> 1 dot -> legitimate
        result = asyncio.run(self.extractor.extract("http://google.com"))
        assert result["features"]["having_Sub_Domain"] == 1

    def test_two_dots_returns_zero(self) -> None:
        # www.google.com -> 2 dots -> suspicious (UCI original semantics, www not stripped)
        result = asyncio.run(self.extractor.extract("http://www.google.com"))
        assert result["features"]["having_Sub_Domain"] == 0

    def test_three_dots_returns_minus_one(self) -> None:
        # login.secure.google.com -> 3 dots -> phishing
        result = asyncio.run(self.extractor.extract("http://login.secure.google.com"))
        assert result["features"]["having_Sub_Domain"] == -1


# ---------------------------------------------------------------------------
# HTTPS_token
# ---------------------------------------------------------------------------

class TestHTTPSToken:
    def setup_method(self) -> None:
        self.extractor = URLFeatureExtractor()

    def test_https_in_hostname_returns_minus_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://https-secure-paypal.com"))
        assert result["features"]["HTTPS_token"] == -1

    def test_normal_hostname_returns_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://paypal.com"))
        assert result["features"]["HTTPS_token"] == 1

    def test_https_scheme_does_not_trigger(self) -> None:
        # https in the scheme only must NOT be flagged
        result = asyncio.run(self.extractor.extract("https://paypal.com"))
        assert result["features"]["HTTPS_token"] == 1


# ---------------------------------------------------------------------------
# port
# ---------------------------------------------------------------------------

class TestPort:
    def setup_method(self) -> None:
        self.extractor = URLFeatureExtractor()

    def test_non_standard_port_returns_minus_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://example.com:8080/path"))
        assert result["features"]["port"] == -1

    def test_port_80_returns_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://example.com:80"))
        assert result["features"]["port"] == 1

    def test_no_explicit_port_returns_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://example.com"))
        assert result["features"]["port"] == 1

    def test_port_443_returns_one(self) -> None:
        result = asyncio.run(self.extractor.extract("https://example.com:443"))
        assert result["features"]["port"] == 1


# ---------------------------------------------------------------------------
# Abnormal_URL
# ---------------------------------------------------------------------------

class TestAbnormalURL:
    def setup_method(self) -> None:
        self.extractor = URLFeatureExtractor()

    def test_normal_url_returns_one(self) -> None:
        result = asyncio.run(self.extractor.extract("http://example.com"))
        assert result["features"]["Abnormal_URL"] == 1

    def test_fake_credential_with_domain_returns_minus_one(self) -> None:
        # paypal.com@evil.com — embedded domain in credential
        result = asyncio.run(self.extractor.extract("http://paypal.com@evil.com"))
        assert result["features"]["Abnormal_URL"] == -1

    def test_embedded_redirect_in_path_returns_minus_one(self) -> None:
        result = asyncio.run(
            self.extractor.extract("http://evil.com/redirect?to=http://other.com")
        )
        assert result["features"]["Abnormal_URL"] == -1


# ---------------------------------------------------------------------------
# Integration tests on the extractor
# ---------------------------------------------------------------------------

class TestExtractorIntegration:
    def setup_method(self) -> None:
        self.extractor = URLFeatureExtractor()

    def test_extract_returns_exactly_30_features(self) -> None:
        result = asyncio.run(self.extractor.extract("http://bit.ly/abc"))
        assert len(result["features"]) == 30

    def test_unimplemented_features_use_fallback_zero(self) -> None:
        result = asyncio.run(self.extractor.extract("http://example.com"))
        non_implemented = [f for f in FEATURE_ORDER if f not in {
            "having_IP_Address", "URL_Length", "Shortining_Service",
            "having_At_Symbol", "double_slash_redirecting", "Prefix_Suffix",
            "having_Sub_Domain", "HTTPS_token", "port", "Abnormal_URL",
        }]
        for feature in non_implemented:
            assert result["features"][feature] == 0, (
                f"{feature} should be fallback 0, got {result['features'][feature]}"
            )

    def test_shortening_service_detected_via_extract(self) -> None:
        result = asyncio.run(self.extractor.extract("http://bit.ly/abc"))
        assert result["features"]["Shortining_Service"] == -1

    def test_ip_address_detected_via_extract(self) -> None:
        result = asyncio.run(self.extractor.extract("http://192.168.0.1"))
        assert result["features"]["having_IP_Address"] == -1
