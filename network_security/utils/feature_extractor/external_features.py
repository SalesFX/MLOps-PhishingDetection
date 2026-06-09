import asyncio
import ipaddress
import os
from urllib.parse import urlparse

import httpx

from network_security.utils.feature_extractor.url_validator import _is_blocked_ip

TRANCO_API_URL = "https://tranco-list.eu/api/ranks/domain/{domain}"
GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
EXTERNAL_TIMEOUT = 8.0  # segundos

TRANCO_TOP_THRESHOLD = 100_000   # rank <= 100k -> 1 (popular/legit)
TRANCO_MID_THRESHOLD = 500_000   # rank <= 500k -> 0 (medio), > 500k -> -1


def _extract_domain(url: str) -> str:
    return urlparse(url).hostname or ""


def _hostname_is_blocked(url: str) -> bool:
    """True se o hostname da URL e um IP em faixa bloqueada (privado, loopback, etc.).

    Apenas IPs literais sao verificados; dominios normais nao sao resolvidos aqui
    para evitar DNS lookup desnecessario na verificacao SSRF basica.
    """
    hostname = urlparse(url).hostname or ""
    if not hostname:
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        return _is_blocked_ip(str(addr))
    except ValueError:
        return False  # dominio normal, nao bloquear


async def feat_web_traffic(url: str) -> tuple[int, str]:
    """Consulta Tranco para obter ranking de popularidade do dominio.

    NOTA: Tranco mede popularidade/trafego, nao seguranca. E um sinal auxiliar.
    Rank alto (popular) sugere site legitimo; rank baixo ou ausente sugere suspeito.

    Retorna (valor, warning_msg).
    """
    domain = _extract_domain(url)
    if not domain:
        return 0, "web_traffic: fallback neutro (dominio nao extraido)"

    try:
        async with httpx.AsyncClient(timeout=EXTERNAL_TIMEOUT) as client:
            resp = await client.get(TRANCO_API_URL.format(domain=domain))
            resp.raise_for_status()
            data = resp.json()
            ranks = data.get("ranks", [])
            if not ranks:
                return 0, "web_traffic: fallback neutro (dominio nao encontrado no Tranco)"
            rank = ranks[0].get("rank")
            if rank is None:
                return 0, "web_traffic: fallback neutro (rank ausente na resposta Tranco)"
            if rank <= TRANCO_TOP_THRESHOLD:
                return 1, "web_traffic: extraido via Tranco (rank popular)"
            if rank <= TRANCO_MID_THRESHOLD:
                return 0, "web_traffic: extraido via Tranco (rank medio)"
            return -1, "web_traffic: extraido via Tranco (rank baixo)"
    except httpx.TimeoutException:
        return 0, "web_traffic: fallback neutro (Tranco timeout)"
    except Exception as e:
        return 0, f"web_traffic: fallback neutro (Tranco erro: {type(e).__name__})"


async def feat_statistical_report(url: str) -> tuple[int, str]:
    """Verifica URL no Google Safe Browsing.

    Requer GOOGLE_SAFE_BROWSING_API_KEY configurado.
    Se a API retornar match de ameaca: -1 (phishing/malware confirmado).
    Se a API retornar URL limpa: 1.
    Se sem chave ou falha: 0 fallback.

    IPs literais em faixas bloqueadas (loopback, privado etc.) nao sao enviados
    ao GSB — consulta seria inutil e potencialmente expoe informacao interna.
    """
    if _hostname_is_blocked(url):
        return 0, "Statistical_report: fallback neutro (URL hostname bloqueado — consulta omitida)"

    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return 0, "Statistical_report: fallback neutro (GOOGLE_SAFE_BROWSING_API_KEY nao configurada)"

    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=EXTERNAL_TIMEOUT) as client:
            resp = await client.post(
                GSB_API_URL,
                params={"key": api_key},
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("matches"):
                return -1, "Statistical_report: extraido via Google Safe Browsing (ameaca detectada)"
            return 1, "Statistical_report: extraido via Google Safe Browsing (URL limpa)"
    except httpx.TimeoutException:
        return 0, "Statistical_report: fallback neutro (Google Safe Browsing timeout)"
    except httpx.HTTPStatusError as e:
        return 0, f"Statistical_report: fallback neutro (Google Safe Browsing HTTP {e.response.status_code})"
    except Exception as e:
        return 0, f"Statistical_report: fallback neutro (Google Safe Browsing erro: {type(e).__name__})"


def feat_page_rank() -> tuple[int, str]:
    """PageRank original do Google e obsoleto desde 2016.

    Open PageRank mede autoridade/SEO, nao phishing — nao implementado.
    Valor mais comum no dataset UCI e -1 (maioria dos sites sem rank).
    Usando fallback 0 conforme convencao do projeto.
    """
    return 0, "Page_Rank: fallback documentado (PageRank obsoleto; alternativa SEO nao relevante para phishing)"


def feat_google_index() -> tuple[int, str]:
    """Verificacao de indexacao pelo Google nao possui API gratuita/oficial simples.

    Scraping do Google viola os termos de uso e nao sera implementado.
    """
    return 0, "Google_Index: fallback documentado (sem API gratuita/oficial; scraping nao utilizado)"


def feat_links_pointing_to_page() -> tuple[int, str]:
    """Contagem de backlinks exige API de analise de links geralmente paga (Moz, Ahrefs, Majestic).

    Correlacao com o dataset e +0.03 (mais fraca das 30 features) — impacto minimo.
    """
    return 0, "Links_pointing_to_page: fallback documentado (API de backlinks paga; correlacao +0.03 no dataset)"


async def extract_external_features(url: str) -> dict[str, object]:
    """Extrai as 5 features externas. Nunca levanta excecao.

    Retorna {"features": dict[str,int], "warnings": list[str]}.
    """
    features: dict[str, int] = {}
    warnings: list[str] = []

    # web_traffic e Statistical_report em paralelo
    traffic_task = asyncio.create_task(feat_web_traffic(url))
    stat_task = asyncio.create_task(feat_statistical_report(url))

    traffic_val, traffic_warn = await traffic_task
    stat_val, stat_warn = await stat_task

    features["web_traffic"] = traffic_val
    warnings.append(traffic_warn)

    features["Statistical_report"] = stat_val
    warnings.append(stat_warn)

    # fallbacks documentados
    _fallback_funcs = [
        ("Page_Rank", feat_page_rank),
        ("Google_Index", feat_google_index),
        ("Links_pointing_to_page", feat_links_pointing_to_page),
    ]
    for feature_name, func in _fallback_funcs:
        val, warn = func()
        features[feature_name] = val
        warnings.append(warn)

    return {"features": features, "warnings": warnings}
