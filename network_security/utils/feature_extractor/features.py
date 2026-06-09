from enum import Enum

# IMPORTANTE — codificacao das features:
# Os valores -1, 0 e 1 seguem a codificacao original do dataset UCI Phishing Websites.
# A interpretacao de cada valor depende da feature especifica e NAO e uniforme:
#   - Para a maioria das features binarias: -1 indica phishing, 1 indica legitimo.
#   - Para algumas features (ex: URL_Length, having_Sub_Domain): 0 indica estado intermediario.
#   - O label final (Result) usa: 1 = legitimo, -1 = phishing (remapeado para 0/1 no treino).
# Nunca assuma que "1 = phishing" ou "-1 = phishing" sem verificar a feature.
# O modelo aprendeu as relacoes corretas; a codificacao aqui deve ser fiel ao dataset.


class FeatureGroup(str, Enum):
    URL_STRING = "url_string"
    HTTP_HTML = "http_html"
    WHOIS_DNS = "whois_dns"
    EXTERNAL_API = "external_api"


# Ordem exata esperada pelo modelo — fonte de verdade.
# Qualquer alteracao aqui invalida o modelo treinado.
FEATURE_ORDER: list[str] = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
]

FEATURE_GROUPS: dict[str, FeatureGroup] = {
    "having_IP_Address": FeatureGroup.URL_STRING,
    "URL_Length": FeatureGroup.URL_STRING,
    "Shortining_Service": FeatureGroup.URL_STRING,
    "having_At_Symbol": FeatureGroup.URL_STRING,
    "double_slash_redirecting": FeatureGroup.URL_STRING,
    "Prefix_Suffix": FeatureGroup.URL_STRING,
    "having_Sub_Domain": FeatureGroup.URL_STRING,
    "port": FeatureGroup.URL_STRING,
    "HTTPS_token": FeatureGroup.URL_STRING,
    "Abnormal_URL": FeatureGroup.URL_STRING,
    "SSLfinal_State": FeatureGroup.HTTP_HTML,
    "Favicon": FeatureGroup.HTTP_HTML,
    "Request_URL": FeatureGroup.HTTP_HTML,
    "URL_of_Anchor": FeatureGroup.HTTP_HTML,
    "Links_in_tags": FeatureGroup.HTTP_HTML,
    "SFH": FeatureGroup.HTTP_HTML,
    "Submitting_to_email": FeatureGroup.HTTP_HTML,
    "Redirect": FeatureGroup.HTTP_HTML,
    "on_mouseover": FeatureGroup.HTTP_HTML,
    "RightClick": FeatureGroup.HTTP_HTML,
    "popUpWidnow": FeatureGroup.HTTP_HTML,
    "Iframe": FeatureGroup.HTTP_HTML,
    "Domain_registeration_length": FeatureGroup.WHOIS_DNS,
    "age_of_domain": FeatureGroup.WHOIS_DNS,
    "DNSRecord": FeatureGroup.WHOIS_DNS,
    "web_traffic": FeatureGroup.EXTERNAL_API,
    "Page_Rank": FeatureGroup.EXTERNAL_API,
    "Google_Index": FeatureGroup.EXTERNAL_API,
    "Links_pointing_to_page": FeatureGroup.EXTERNAL_API,
    "Statistical_report": FeatureGroup.EXTERNAL_API,
}

# Fallback neutro para features nao calculaveis.
# Decisao pragmatica: 0 minimiza vies para features binarias {-1, 1}.
# Limitacao documentada: features onde 0 nao e semanticamente neutro
# (ex: URL_Length) podem introduzir leve distorcao. Ver ADR-003.
FEATURE_FALLBACKS: dict[str, int] = {feature: 0 for feature in FEATURE_ORDER}


def build_feature_vector(features: dict[str, int]) -> list[int]:
    """Monta o vetor de 30 features na ordem exata esperada pelo modelo.

    Features ausentes recebem o valor de fallback definido em FEATURE_FALLBACKS.
    Garante que o vetor sempre tenha exatamente 30 posicoes.
    """
    return [features.get(f, FEATURE_FALLBACKS[f]) for f in FEATURE_ORDER]
