import concurrent.futures
import ipaddress
import socket
from urllib.parse import urlparse


class SSRFBlockedError(ValueError):
    """Raised when a URL is blocked by SSRF protection."""


BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
]


def _is_blocked_ip(ip_str: str) -> bool:
    """Returns True if the IP address must be blocked."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    if (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return True

    for network in BLOCKED_NETWORKS:
        if addr in network:
            return True

    return False


def _resolve_with_timeout(hostname: str, timeout: float) -> list[str]:
    """Resolves a hostname to a list of IP address strings within the given timeout."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            socket.getaddrinfo, hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        try:
            results = future.result(timeout=timeout)
            return [info[4][0] for info in results]
        except concurrent.futures.TimeoutError:
            raise SSRFBlockedError(f"DNS resolution timed out for '{hostname}'")
        except (socket.gaierror, OSError) as e:
            raise SSRFBlockedError(f"DNS resolution failed for '{hostname}': {e}")


def validate_url_for_fetch(url: str, dns_timeout: float = 3.0) -> None:
    """Validates that a URL is safe to fetch.

    Raises SSRFBlockedError if the URL targets a private, loopback, link-local,
    or otherwise restricted address, or uses a disallowed scheme.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise SSRFBlockedError(
            f"Scheme '{parsed.scheme}' is not allowed. Only 'http' and 'https' are permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("URL has no hostname.")

    # Strip IPv6 brackets that urlparse retains in .hostname for bare-IP checks.
    try:
        addr = ipaddress.ip_address(hostname)
        if _is_blocked_ip(str(addr)):
            raise SSRFBlockedError(f"IP address '{hostname}' is blocked.")
        # Hostname is a valid public IP — no DNS resolution needed.
        return
    except ValueError:
        pass

    # Hostname is a domain name: resolve and validate every returned IP.
    resolved_ips = _resolve_with_timeout(hostname, dns_timeout)
    for ip in resolved_ips:
        if _is_blocked_ip(ip):
            raise SSRFBlockedError(
                f"Hostname '{hostname}' resolves to blocked IP '{ip}'."
            )
