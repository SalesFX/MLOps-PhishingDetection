# Security — SSRF Protection

The feature extractor makes outbound HTTP requests, DNS lookups and WHOIS queries based on user-supplied URLs.
Without controls, this creates Server-Side Request Forgery (SSRF) risk — an attacker could craft a URL
that causes the server to reach internal services, cloud metadata endpoints or private network hosts.

---

## What is blocked

### Schemes

Only `http` and `https` are permitted. All other schemes raise `SSRFBlockedError` immediately:

- `file://`
- `ftp://`
- `gopher://`
- `javascript:`
- `data:`
- any other non-http/https scheme

### IP ranges

Direct IP hostnames and domains that resolve to any of the following ranges are blocked:

| Range | Description |
|-------|-------------|
| `127.0.0.0/8` | Loopback |
| `::1/128` | IPv6 loopback |
| `10.0.0.0/8` | Private network |
| `172.16.0.0/12` | Private network |
| `192.168.0.0/16` | Private network |
| `169.254.0.0/16` | Link-local / cloud metadata (AWS, GCP, Azure) |
| `169.254.169.254` | AWS EC2 instance metadata endpoint |
| `fc00::/7` | IPv6 unique local |
| `fe80::/10` | IPv6 link-local |
| `0.0.0.0/8` | Reserved |
| `100.64.0.0/10` | Carrier-grade NAT |

Additionally, any IP flagged by Python's `ipaddress` as `is_loopback`, `is_private`, `is_link_local`, `is_multicast`, `is_reserved` or `is_unspecified` is blocked.

### DNS resolution

For domain-based hostnames, DNS is resolved with a 5-second timeout before any HTTP request is made.
**Every resolved IP** is checked against the blocked ranges. If any resolved address falls in a blocked range, the request is denied.

This prevents DNS rebinding attacks where an attacker controls a domain that resolves to a private IP.

### WHOIS and DNS lookups

Before performing DNS lookups or WHOIS queries, the hostname is validated:
- Direct IPs in blocked ranges skip WHOIS (no external lookup performed)
- Blocked private IPs return fallback `0` for `DNSRecord` without making any query

### Google Safe Browsing

Before submitting a URL to the Safe Browsing API, the URL's hostname is checked for blocked IP ranges.
If the hostname is a private/loopback IP, the API call is skipped and fallback `0` is returned.
Note: the URL is sent as data in a POST body to a trusted external API — SSRF does not apply to the API endpoint itself.

### Redirects

HTTP requests use `follow_redirects=False`. The `Redirect` feature is set to `-1` if the response is 3xx.
The redirect target is not fetched, preventing a bypass where a safe-looking URL redirects to a private address.

---

## Implementation

```
network_security/utils/feature_extractor/url_validator.py
```

Key functions:
- `validate_url_for_fetch(url)` — raises `SSRFBlockedError` for any blocked URL
- `_is_blocked_ip(ip_str)` — returns `True` for any blocked IP range
- `_resolve_with_timeout(hostname, timeout)` — DNS lookup with timeout and per-IP validation

`SSRFBlockedError` inherits from `ValueError`. Any feature extraction code that calls external services must call `validate_url_for_fetch` first and handle `SSRFBlockedError` as a fallback trigger, not a hard error.

---

## Test coverage

All SSRF scenarios are tested in `tests/utils/test_url_validator.py` with mocked DNS:

- localhost string → blocked
- 127.0.0.1 → blocked
- 192.168.x.x → blocked
- 10.x.x.x → blocked
- 172.16.x.x → blocked
- 169.254.169.254 → blocked
- IPv6 loopback → blocked
- file://, ftp://, gopher://, javascript:, data: → blocked
- Domain resolving to private IP → blocked (DNS mock)
- DNS timeout → blocked
- https://example.com (public IP) → allowed
