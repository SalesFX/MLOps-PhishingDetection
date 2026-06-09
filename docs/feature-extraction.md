# Feature Extraction

The system extracts 30 numerical features from a URL, matching the UCI Phishing Websites dataset encoding.
All features are integers. Most use a three-value scale: `1` (legitimate signal), `0` (neutral/suspicious), `-1` (phishing signal).
The exact semantics vary per feature — see the table below.

> Source of truth: `network_security/utils/feature_extractor/features.py`

---

## Feature Groups

### Group 1 — URL String (10 features)

Extracted from the URL string alone. No network calls. Instantaneous.

| Feature | Values | Phishing signal |
|---------|--------|-----------------|
| `having_IP_Address` | -1, 1 | -1 if hostname is an IP address |
| `URL_Length` | -1, 0, 1 | -1 if > 75 chars, 0 if 54-75, 1 if < 54 |
| `Shortining_Service` | -1, 1 | -1 if known URL shortener (bit.ly, tinyurl, etc.) |
| `having_At_Symbol` | -1, 1 | -1 if `@` present in URL |
| `double_slash_redirecting` | -1, 1 | -1 if `//` appears after position 6 |
| `Prefix_Suffix` | -1, 1 | -1 if `-` present in hostname |
| `having_Sub_Domain` | -1, 0, 1 | 1 dot=1, 2 dots=0, 3+ dots=-1 |
| `HTTPS_token` | -1, 1 | -1 if `https` appears in the hostname itself |
| `port` | -1, 1 | -1 if non-standard port (not 80 or 443) |
| `Abnormal_URL` | -1, 1 | -1 if URL has `@`-redirect pattern or embedded scheme in path |

---

### Group 2 — HTTP / HTML (12 features)

A single HTTP GET (with SSRF validation, `follow_redirects=False`, 10s timeout). HTML parsed with BeautifulSoup.

| Feature | Values | Rule |
|---------|--------|------|
| `SSLfinal_State` | -1, 0, 1 | 1 = HTTPS + 2xx; 0 = error; -1 = HTTP |
| `Favicon` | -1, 1 | -1 if favicon loaded from external domain |
| `Request_URL` | -1, 0, 1 | % of external resources (img, script, link, audio, video): < 22% → 1, 22-61% → 0, > 61% → -1 |
| `URL_of_Anchor` | -1, 0, 1 | % of suspicious anchors (external, `#`, `javascript:`): < 31% → 1, 31-67% → 0, > 67% → -1 |
| `Links_in_tags` | -1, 0, 1 | % of external links in `<meta>`, `<script>`, `<link>`: < 17% → 1, 17-81% → 0, > 81% → -1 |
| `SFH` | -1, 0, 1 | Server Form Handler: 1 = valid action, 0 = blank/about:blank, -1 = external domain |
| `Submitting_to_email` | -1, 1 | -1 if any form action uses `mailto:` |
| `Redirect` | -1, 1 | -1 if HTTP response is 3xx |
| `on_mouseover` | -1, 1 | -1 if `onmouseover` found in HTML |
| `RightClick` | -1, 1 | -1 if right-click blocking detected (`oncontextmenu`, `event.button==2`) |
| `popUpWidnow` | -1, 1 | -1 if `window.open` found in HTML (*typo preserved from UCI dataset*) |
| `Iframe` | -1, 1 | -1 if `<iframe>` or `<frame>` tag found |

If the HTTP fetch fails (timeout, SSRF blocked, unreachable host), all 12 features fall back to `0`.

---

### Group 3 — DNS / WHOIS (3 features)

DNS lookup via `socket.getaddrinfo` (5s timeout). WHOIS via `python-whois` (10s timeout, thread-isolated).

| Feature | Values | Rule |
|---------|--------|------|
| `DNSRecord` | -1, 1 | 1 if domain resolves; -1 if DNS fails |
| `age_of_domain` | -1, 1 | 1 if created > 180 days ago; -1 if recent |
| `Domain_registeration_length` | -1, 1 | 1 if expiration > 365 days away; -1 if soon |

WHOIS is skipped for direct IP addresses. On failure, fallback `0` is returned with a warning.

---

### Group 4 — External APIs (2 active, 3 documented fallback)

#### Active integrations

| Feature | Source | Values | Rule |
|---------|--------|--------|------|
| `web_traffic` | Tranco API | -1, 0, 1 | rank ≤ 100k → 1; ≤ 500k → 0; > 500k → -1; no rank → 0 |
| `Statistical_report` | Google Safe Browsing | -1, 1 | -1 if URL matches a threat; 1 if clean; 0 if key absent or error |

`Statistical_report` requires `GOOGLE_SAFE_BROWSING_API_KEY`. Without it, fallback `0` is returned.
Tranco is a public API — no key required.

#### Documented fallbacks (permanent)

| Feature | Reason |
|---------|--------|
| `Page_Rank` | PageRank API discontinued in 2016. Open PageRank measures SEO authority, not phishing risk. |
| `Google_Index` | No free/official API for indexation checks. Scraping Google violates terms of use. |
| `Links_pointing_to_page` | Backlink data requires paid APIs (Moz, Ahrefs). Correlation with phishing is +0.03 in the dataset. |

---

## Fallback Strategy

The model always receives a vector of exactly 30 values. Features that cannot be extracted receive value `0` (neutral fallback).

**Why `0`:** most UCI features are binary {-1, 1}. Zero sits between both poles, minimising bias. Exception: features like `URL_Length` where `0` never appears naturally — acknowledged as a documented limitation.

Every fallback feature appears in the `warnings` array of the API response. The `extraction_status` field shows how many features were calculated vs. fell back.

With all integrations configured:
- **27 calculated** / 3 documented fallback (Page_Rank, Google_Index, Links_pointing_to_page)
- Without Google Safe Browsing key: **26 calculated** / 4 fallback
