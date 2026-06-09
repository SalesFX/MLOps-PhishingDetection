# Design Spec — URL Prediction Feature
> Data: 2026-06-09
> Status: aprovado

---

## Contexto

O modelo atual aceita um CSV com 30 features numericas pre-extraidas e retorna se uma URL e phishing ou legitima. Para usar o sistema e necessario montar o CSV manualmente, o que nao e pratico. Este spec descreve a evolucao para aceitar uma URL bruta como entrada.

---

## Arquitetura

### Novo modulo: `network_security/utils/feature_extractor/`

- `features.py` — lista ordenada das 30 features, grupos, valores de fallback
- `extractor.py` — classe `URLFeatureExtractor` com metodo `async extract(url: str) -> dict[str, int]`

Grupos de extracao executados em paralelo via `asyncio`:

| Grupo | Features | Dependencias | Timeout |
|-------|----------|--------------|---------|
| URL string | ~10 features | nenhuma (regex/parse) | instantaneo |
| HTTP/HTML | ~12 features | `httpx`, `beautifulsoup4` | 15s |
| WHOIS/DNS | ~3 features | `python-whois`, `dnspython` | 8s |
| APIs externas | ~5 features | Tranco, PhishTank (opcionais) | 5s, fallback 0 |

### Novo endpoint: `POST /predict-url`

Request:
```json
{ "url": "https://exemplo.com" }
```

Response:
```json
{
  "url": "https://exemplo.com",
  "prediction": "phishing",
  "confidence": 0.94,
  "features": { "having_IP_Address": -1, "URL_Length": 1, ... },
  "extraction_status": "partial",
  "warnings": ["web_traffic: fallback neutro usado"]
}
```

O endpoint `/predict` (CSV) permanece intocado.

### Interface web (nova pagina `/`)

- Campo de texto para URL
- Botao "Verificar"
- Estado de loading assincrono via `fetch` para `/predict-url`
- Badge colorido: vermelho (phishing) / verde (legitima)
- Historico das ultimas predicoes da sessao (localStorage ou in-memory JS)
- Bloco colapsavel com as 30 features calculadas e seus valores

---

## Tratamento de erros e fallback

- Qualquer feature nao calculavel usa valor neutro `0` e gera um `warning`
- Falhas em servicos externos (HTTP timeout, WHOIS indisponivel, API externa down) nunca quebram a predicao
- Se a URL alvo estiver fora do ar, features do grupo HTTP ficam todas em `0` com warning

---

## Testes

- Unitarios para cada feature com mocks — sem internet real
- Integracao para `POST /predict-url` com URL mockada
- Nenhum teste depende de conectividade externa
- Cobertura minima: todas as features do grupo URL string (sem dependencia de rede)

---

## Dependencias novas

```
httpx
beautifulsoup4
python-whois
dnspython
```

---

## Plano de etapas

Ver `docs/adr/` para decisoes e spec do usuario para as 10 etapas incrementais.

---

## Restricoes

- Ordem das 30 features deve ser identica ao schema do modelo
- Endpoint `/predict` nao pode ser alterado
- Nenhum teste pode depender de internet real
- Fallback nunca gera erro fatal, sempre gera warning
