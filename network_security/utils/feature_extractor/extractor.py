from network_security.utils.feature_extractor.features import (
    FEATURE_FALLBACKS,
    FEATURE_ORDER,
    build_feature_vector,
)


class URLFeatureExtractor:
    """Extrai as 30 features numericas a partir de uma URL bruta.

    Estrutura preparada para implementacao incremental:
    - Etapa 1 (atual): retorna todos os fallbacks
    - Etapa 2: features extraidas da string da URL
    - Etapa 3+: features HTTP/HTML, WHOIS/DNS, APIs externas
    """

    async def extract(self, url: str) -> dict[str, int]:
        """Extrai features da URL e retorna dict com exatamente 30 entradas.

        Features nao implementadas retornam o valor de fallback (0).
        """
        features: dict[str, int] = dict(FEATURE_FALLBACKS)
        warnings: list[str] = [
            f"{f}: fallback neutro (extracao nao implementada)" for f in FEATURE_ORDER
        ]
        return {"features": features, "warnings": warnings}

    def build_vector(self, features: dict[str, int]) -> list[int]:
        """Monta o vetor ordenado de 30 posicoes para o modelo."""
        return build_feature_vector(features)
