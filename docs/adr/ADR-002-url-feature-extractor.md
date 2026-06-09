# ADR-002 — Modulo isolado de extracao de features

**Status:** aceito
**Data:** 2026-06-09

---

## Contexto

A extracao das 30 features a partir de uma URL bruta envolve logica heterogenea: parse de string, requisicoes HTTP, consultas DNS/WHOIS e chamadas a APIs externas. Colocar essa logica diretamente no endpoint ou no pipeline de treinamento criaria acoplamento e dificultaria testes.

## Decisao

Criar o modulo `network_security/utils/feature_extractor/` com dois arquivos:

- `features.py`: lista ordenada das 30 features, agrupamento por tipo de extracao e valores de fallback
- `extractor.py`: classe `URLFeatureExtractor` com metodo `async extract(url: str) -> dict[str, int]`. O parse puro da URL e sincrono. Operacoes HTTP e chamadas a APIs externas podem usar `asyncio` quando a concorrencia for vantajosa. Consultas WHOIS e DNS, quando necessario, sao executadas com timeout em thread separada via `asyncio.to_thread` para nao bloquear o event loop.

O modulo e agnnostico ao modelo — apenas extrai features, nao faz inferencia.

## Consequencias

- Testavel de forma independente com mocks
- Reutilizavel por qualquer futuro endpoint ou script batch
- A ordem das features em `features.py` e a fonte de verdade, garantindo que o vetor enviado ao modelo esteja sempre correto
- Adiciona dependencias: `httpx`, `beautifulsoup4`, `python-whois`, `dnspython`

## Alternativas consideradas

- **Logica inline no endpoint:** simples de comecar, mas intestavel e impossivel de reutilizar
- **Script separado fora do pacote:** quebraria a convencao de modulos do projeto
