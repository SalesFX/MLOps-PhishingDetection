import ipaddress
from urllib.parse import urlparse, ParseResult

from network_security.utils.feature_extractor.dns_whois_features import (
    extract_dns_whois_features,
)
from network_security.utils.feature_extractor.features import (
    FEATURE_FALLBACKS,
    FEATURE_ORDER,
    build_feature_vector,
)
from network_security.utils.feature_extractor.http_features import (
    extract_http_features,
)

_SHORTENING_SERVICES: frozenset[str] = frozenset({
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "cli.gs",
    "tr.im", "u.to", "su.pr", "twurl.nl", "snipurl.com", "short.to", "ping.fm",
    "post.ly", "bkite.com", "snipr.com", "doiop.com", "kl.am", "wp.me",
    "om.ly", "to.ly", "bit.do", "buff.ly", "rb.gy", "x.co", "shorte.st",
    "cutt.ly",
})

# Features calculadas a partir da string da URL.
# As demais 8 features (WHOIS/DNS, APIs externas) continuam usando fallback (0).
_IMPLEMENTED_STRING_FEATURES: frozenset[str] = frozenset({
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "HTTPS_token",
    "port",
    "Abnormal_URL",
})


class URLFeatureExtractor:
    """Extrai as 30 features numericas a partir de uma URL bruta.

    Estrutura preparada para implementacao incremental:
    - Etapa 1: retornava todos os fallbacks
    - Etapa 2: 10 features extraidas da string da URL
    - Etapa 5: 12 features HTTP/HTML adicionadas via fetch real
    - Etapa 6 (atual): 3 features DNS/WHOIS adicionadas
    - Etapa 7+: features de APIs externas
    """

    async def extract(self, url: str) -> dict[str, object]:
        """Extrai features da URL e retorna dict com exatamente 30 entradas.

        Features nao implementadas retornam o valor de fallback (0).
        Retorna {"features": dict[str, int], "warnings": list[str]}.
        """
        normalized = self._normalize(url)
        parsed: ParseResult = urlparse(normalized)
        hostname: str = parsed.hostname or ""

        computed: dict[str, int] = {
            "having_IP_Address": self._having_ip_address(hostname),
            "URL_Length": self._url_length(normalized),
            "Shortining_Service": self._shortining_service(hostname),
            "having_At_Symbol": self._having_at_symbol(normalized),
            "double_slash_redirecting": self._double_slash_redirecting(normalized),
            "Prefix_Suffix": self._prefix_suffix(hostname),
            "having_Sub_Domain": self._having_sub_domain(hostname),
            "HTTPS_token": self._https_token(hostname),
            "port": self._port(parsed),
            "Abnormal_URL": self._abnormal_url(normalized, parsed),
        }

        http_result = await extract_http_features(normalized)
        computed.update(http_result["features"])  # type: ignore[arg-type]

        dns_whois_result = await extract_dns_whois_features(normalized)
        computed.update(dns_whois_result["features"])  # type: ignore[arg-type]

        features: dict[str, int] = dict(FEATURE_FALLBACKS)
        features.update(computed)

        # Build warnings in FEATURE_ORDER so the caller can rely on position.
        # HTTP and DNS/WHOIS warnings are keyed by feature name (text before first ':').
        http_warnings: dict[str, str] = {
            w.split(":")[0]: w for w in http_result["warnings"]  # type: ignore[union-attr]
        }
        dns_whois_warnings: dict[str, str] = {
            w.split(":")[0]: w for w in dns_whois_result["warnings"]  # type: ignore[union-attr]
        }

        warnings: list[str] = []
        for f in FEATURE_ORDER:
            if f in _IMPLEMENTED_STRING_FEATURES:
                warnings.append(f"{f}: extraido da string da URL")
            elif f in http_warnings:
                warnings.append(http_warnings[f])
            elif f in dns_whois_warnings:
                warnings.append(dns_whois_warnings[f])
            else:
                warnings.append(f"{f}: fallback neutro (extracao nao implementada)")

        return {"features": features, "warnings": warnings}

    def build_vector(self, features: dict[str, int]) -> list[int]:
        """Monta o vetor ordenado de 30 posicoes para o modelo."""
        return build_feature_vector(features)

    def _normalize(self, url: str) -> str:
        """Adiciona scheme http:// se a URL nao tiver scheme."""
        if "://" not in url:
            return "http://" + url
        return url

    def _having_ip_address(self, hostname: str) -> int:
        """Retorna -1 se o hostname e um endereco IP (v4 ou v6), 1 se e dominio."""
        try:
            ipaddress.ip_address(hostname)
            return -1
        except ValueError:
            return 1

    def _url_length(self, url: str) -> int:
        """1 se < 54 chars (legitimo), 0 se 54-75 (suspeito), -1 se > 75 (phishing)."""
        length = len(url)
        if length < 54:
            return 1
        if length <= 75:
            return 0
        return -1

    def _shortining_service(self, hostname: str) -> int:
        """Retorna -1 se o hostname pertence a um servico de encurtamento conhecido."""
        if hostname.lower() in _SHORTENING_SERVICES:
            return -1
        return 1

    def _having_at_symbol(self, url: str) -> int:
        """Retorna -1 se '@' esta presente na URL (pode mascarar o host real)."""
        if "@" in url:
            return -1
        return 1

    def _double_slash_redirecting(self, url: str) -> int:
        """Retorna -1 se '//' aparece apos a posicao 6, indicando redirect embutido."""
        if url.rfind("//") > 6:
            return -1
        return 1

    def _prefix_suffix(self, hostname: str) -> int:
        """Retorna -1 se '-' esta no hostname (comum em dominios de phishing)."""
        if "-" in hostname:
            return -1
        return 1

    def _having_sub_domain(self, hostname: str) -> int:
        """Conta pontos no hostname sem remover 'www.' — semantica original do UCI.

        www.google.com tem 2 pontos e e classificado como suspeito (0) pelo dataset.
        Remover 'www.' antes de contar alteraria a semantica treinada.

        1 ponto -> legitimo (1)
        2 pontos -> suspeito (0)
        3+ pontos -> phishing (-1)
        """
        dot_count = hostname.count(".")
        if dot_count == 1:
            return 1
        if dot_count == 2:
            return 0
        return -1

    def _https_token(self, hostname: str) -> int:
        """Retorna -1 se 'https' aparece no proprio hostname (ex: https-secure-paypal.com).

        Apenas o hostname e verificado; o scheme da URL nao e considerado.
        """
        if "https" in hostname.lower():
            return -1
        return 1

    def _port(self, parsed: ParseResult) -> int:
        """Retorna -1 se a URL usa porta nao-padrao (diferente de 80 e 443)."""
        port = parsed.port
        if port is not None and port not in (80, 443):
            return -1
        return 1

    def _abnormal_url(self, url: str, parsed: ParseResult) -> int:
        """Detecta anomalias estruturais na URL sem chamadas de rede.

        Implementacao string-only: a versao completa do UCI requer consulta WHOIS
        para verificar se o hostname aparece na URL de forma inconsistente.

        Casos cobertos:
        - Credencial falsa com dominio embutido: user@evil.com onde 'user' contem ponto
        - Redirect embutido no path: path contem http:// ou https://
        """
        # Credencial falsa: a parte antes de '@' (sem o scheme) contem ponto
        if "@" in url:
            # Remove o scheme para isolar a parte de autoridade/credencial
            without_scheme = url.split("://", 1)[-1]
            before_at = without_scheme.split("@")[0]
            if "." in before_at:
                return -1

        # Redirect embutido no path
        path = parsed.path or ""
        query = parsed.query or ""
        full_path = path + ("?" + query if query else "")
        if "http://" in full_path or "https://" in full_path:
            return -1

        return 1
