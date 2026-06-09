import concurrent.futures
import ipaddress
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import whois

from network_security.utils.feature_extractor.url_validator import _is_blocked_ip

DNS_TIMEOUT = 5.0
WHOIS_TIMEOUT = 10.0
AGE_THRESHOLD_DAYS = 180
REGISTRATION_THRESHOLD_DAYS = 365


def _extract_hostname(url: str) -> str:
    """Extrai hostname da URL. Retorna '' se inválido."""
    return urlparse(url).hostname or ""


def _is_ip_hostname(hostname: str) -> bool:
    """True se hostname é um endereço IP (v4 ou v6)."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_blocked_hostname(hostname: str) -> bool:
    """True se hostname é IP em faixa bloqueada (privado, loopback, link-local etc.)."""
    if _is_ip_hostname(hostname):
        return _is_blocked_ip(hostname)
    return False


def _normalize_date(value: object) -> datetime | None:
    """Normaliza creation_date ou expiration_date que podem ser datetime, list ou None."""
    if value is None:
        return None
    if isinstance(value, list):
        valid = [v for v in value if isinstance(v, datetime)]
        return valid[0] if valid else None
    if isinstance(value, datetime):
        return value
    return None


def _resolve_dns(hostname: str, timeout: float = DNS_TIMEOUT) -> bool:
    """Tenta resolver DNS para hostname. Retorna True se resolve, False se falha/timeout."""
    def _lookup() -> list[object]:
        return socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_lookup)
        try:
            future.result(timeout=timeout)
            return True
        except (concurrent.futures.TimeoutError, socket.gaierror, OSError):
            return False


def _fetch_whois(hostname: str, timeout: float = WHOIS_TIMEOUT) -> "whois.WhoisEntry | None":
    """Busca WHOIS com timeout. Retorna None em caso de falha."""
    def _lookup() -> "whois.WhoisEntry":
        return whois.whois(hostname)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_lookup)
        try:
            return future.result(timeout=timeout)
        except Exception:
            return None


def feat_dns_record(hostname: str) -> int:
    """1 se domínio resolve DNS corretamente, -1 se não resolve.

    UCI: sites sem registro DNS tendem a ser phishing.
    Para IPs diretos: tenta resolver o próprio IP (sempre resolve, retorna 1).
    """
    if not hostname:
        return 0
    if _is_blocked_hostname(hostname):
        return 0
    if _resolve_dns(hostname):
        return 1
    return -1


def feat_age_of_domain(w: "whois.WhoisEntry | None") -> int:
    """1 se domínio tem > 6 meses de existência (criação), -1 se ≤ 6 meses.

    UCI: phishers registram domínios recentemente.
    Threshold: 180 dias desde creation_date.
    """
    if w is None:
        return 0
    creation = _normalize_date(w.get("creation_date"))
    if creation is None:
        return 0
    if creation.tzinfo is None:
        creation = creation.replace(tzinfo=timezone.utc)
    now = datetime.now(tz=timezone.utc)
    age_days = (now - creation).days
    return 1 if age_days > AGE_THRESHOLD_DAYS else -1


def feat_domain_registration_length(w: "whois.WhoisEntry | None") -> int:
    """1 se expiração > 1 ano no futuro, -1 se ≤ 1 ano ou expirado.

    UCI: phishers não pagam por registro longo.
    Threshold: 365 dias até expiration_date.
    """
    if w is None:
        return 0
    expiration = _normalize_date(w.get("expiration_date"))
    if expiration is None:
        return 0
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=timezone.utc)
    now = datetime.now(tz=timezone.utc)
    days_remaining = (expiration - now).days
    return 1 if days_remaining > REGISTRATION_THRESHOLD_DAYS else -1


async def extract_dns_whois_features(url: str) -> dict[str, object]:
    """Extrai as 3 features DNS/WHOIS. Nunca levanta exceção.

    Usa asyncio.to_thread para operações bloqueantes DNS/WHOIS.
    Retorna {"features": dict[str,int], "warnings": list[str]}.
    """
    import asyncio

    hostname = _extract_hostname(url)
    features: dict[str, int] = {}
    warnings: list[str] = []

    if not hostname or _is_blocked_hostname(hostname):
        features["DNSRecord"] = 0
        reason = "hostname vazio" if not hostname else f"IP bloqueado ({hostname})"
        warnings.append(f"DNSRecord: fallback neutro ({reason})")
    else:
        try:
            dns_val = await asyncio.to_thread(feat_dns_record, hostname)
            features["DNSRecord"] = dns_val
            warnings.append("DNSRecord: extraido via DNS")
        except Exception as e:
            features["DNSRecord"] = 0
            warnings.append(f"DNSRecord: fallback neutro (erro: {e})")

    whois_result: "whois.WhoisEntry | None" = None
    whois_error: str | None = None

    if not _is_ip_hostname(hostname) and hostname:
        try:
            whois_result = await asyncio.to_thread(_fetch_whois, hostname)
            if whois_result is None:
                whois_error = "WHOIS lookup falhou ou excedeu timeout"
        except Exception as e:
            whois_error = str(e)
    else:
        whois_error = "IP direto — WHOIS de domínio não aplicável"

    try:
        age_val = feat_age_of_domain(whois_result)
        features["age_of_domain"] = age_val
        if whois_error or whois_result is None:
            warnings.append(
                f"age_of_domain: fallback neutro ({whois_error or 'WHOIS indisponível'})"
            )
            features["age_of_domain"] = 0
        elif age_val == 0:
            warnings.append("age_of_domain: fallback neutro (creation_date ausente no WHOIS)")
        else:
            warnings.append("age_of_domain: extraido via WHOIS")
    except Exception as e:
        features["age_of_domain"] = 0
        warnings.append(f"age_of_domain: fallback neutro (erro: {e})")

    try:
        reg_val = feat_domain_registration_length(whois_result)
        features["Domain_registeration_length"] = reg_val
        if whois_error or whois_result is None:
            warnings.append(
                f"Domain_registeration_length: fallback neutro ({whois_error or 'WHOIS indisponível'})"
            )
            features["Domain_registeration_length"] = 0
        elif reg_val == 0:
            warnings.append(
                "Domain_registeration_length: fallback neutro (expiration_date ausente no WHOIS)"
            )
        else:
            warnings.append("Domain_registeration_length: extraido via WHOIS")
    except Exception as e:
        features["Domain_registeration_length"] = 0
        warnings.append(f"Domain_registeration_length: fallback neutro (erro: {e})")

    return {"features": features, "warnings": warnings}
