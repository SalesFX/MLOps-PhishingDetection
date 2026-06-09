import socket
from unittest.mock import patch

import pytest

from network_security.utils.feature_extractor.url_validator import (
    SSRFBlockedError,
    validate_url_for_fetch,
)

# ---------------------------------------------------------------------------
# Helpers — pre-built mock getaddrinfo return values
# ---------------------------------------------------------------------------

_PUBLIC_IP = "8.8.8.8"
_MOCK_PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_IP, 0))]
_MOCK_PRIVATE = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0))]
_MOCK_LOOPBACK = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

_DNS_PATCH = "network_security.utils.feature_extractor.url_validator.socket.getaddrinfo"


# ---------------------------------------------------------------------------
# Direct-IP tests (no DNS mock required)
# ---------------------------------------------------------------------------


def test_localhost_string_is_blocked() -> None:
    with patch(_DNS_PATCH, return_value=_MOCK_LOOPBACK):
        with pytest.raises(SSRFBlockedError):
            validate_url_for_fetch("http://localhost/path")


def test_127_0_0_1_is_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        validate_url_for_fetch("http://127.0.0.1/")


def test_192_168_0_1_is_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        validate_url_for_fetch("http://192.168.0.1/")


def test_10_0_0_1_is_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        validate_url_for_fetch("http://10.0.0.1/")


def test_172_16_0_1_is_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        validate_url_for_fetch("http://172.16.0.1/")


def test_169_254_169_254_is_blocked() -> None:
    """Cloud metadata endpoint must always be blocked."""
    with pytest.raises(SSRFBlockedError):
        validate_url_for_fetch("http://169.254.169.254/")


def test_ipv6_loopback_is_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        validate_url_for_fetch("http://[::1]/")


# ---------------------------------------------------------------------------
# Scheme tests
# ---------------------------------------------------------------------------


def test_file_scheme_is_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        validate_url_for_fetch("file:///etc/passwd")


def test_ftp_scheme_is_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        validate_url_for_fetch("ftp://example.com/")


def test_gopher_scheme_is_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        validate_url_for_fetch("gopher://example.com/")


def test_javascript_scheme_is_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        validate_url_for_fetch("javascript:alert(1)")


def test_data_scheme_is_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        validate_url_for_fetch("data:text/html,<h1>hi</h1>")


# ---------------------------------------------------------------------------
# Allowed URLs (DNS mocked to a public IP)
# ---------------------------------------------------------------------------


@patch(_DNS_PATCH, return_value=_MOCK_PUBLIC)
def test_https_example_com_is_allowed(mock_dns: object) -> None:
    validate_url_for_fetch("https://example.com")


@patch(_DNS_PATCH, return_value=_MOCK_PUBLIC)
def test_http_example_com_is_allowed(mock_dns: object) -> None:
    validate_url_for_fetch("http://example.com")


# ---------------------------------------------------------------------------
# Domain resolving to private IP
# ---------------------------------------------------------------------------


@patch(_DNS_PATCH, return_value=_MOCK_PRIVATE)
def test_domain_resolving_to_private_ip_is_blocked(mock_dns: object) -> None:
    with pytest.raises(SSRFBlockedError):
        validate_url_for_fetch("http://internal.corp/")


# ---------------------------------------------------------------------------
# DNS failure cases
# ---------------------------------------------------------------------------


@patch(
    _DNS_PATCH,
    side_effect=socket.gaierror("Name or service not known"),
)
def test_dns_failure_raises_ssrf_error(mock_dns: object) -> None:
    with pytest.raises(SSRFBlockedError, match="DNS resolution failed"):
        validate_url_for_fetch("http://nonexistent.invalid/")


def test_dns_timeout_raises_ssrf_error() -> None:
    import concurrent.futures

    # Patch ThreadPoolExecutor.submit so future.result() raises TimeoutError.
    original_executor = __import__(
        "concurrent.futures", fromlist=["ThreadPoolExecutor"]
    ).ThreadPoolExecutor

    class _TimingOutExecutor(original_executor):  # type: ignore[misc]
        def submit(self, fn, *args, **kwargs):  # type: ignore[override]
            future: concurrent.futures.Future = concurrent.futures.Future()
            future.set_exception(concurrent.futures.TimeoutError())
            return future

    with patch(
        "network_security.utils.feature_extractor.url_validator.concurrent.futures.ThreadPoolExecutor",
        _TimingOutExecutor,
    ):
        with pytest.raises(SSRFBlockedError, match="timed out"):
            validate_url_for_fetch("http://slow-dns.example.com/")
