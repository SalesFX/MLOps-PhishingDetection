# ADR-005 — Estrategia de testes para predicao por URL

**Status:** aceito
**Data:** 2026-06-09

---

## Contexto

O feature extractor depende de HTTP, DNS, WHOIS e APIs externas. Testes que dependem de internet real sao lentos, frageis e nao reproduziveis em CI. O endpoint `/predict-url` precisa ser testavel sem subir o modelo real.

## Decisao

Toda dependencia externa e mockada nos testes:

- **Grupo URL string:** testes unitarios puros, sem mock (sem dependencia de rede)
- **Grupo HTTP/HTML:** `httpx` mockado com `respx` ou `unittest.mock` — retorna HTML fixo
- **Grupo WHOIS/DNS:** `python-whois` e `dnspython` mockados com `unittest.mock.patch`
- **Grupo APIs externas:** mockados, testando tanto o caminho de sucesso quanto o fallback
- **Endpoint `/predict-url`:** teste de integracao com modelo mockado via `unittest.mock.patch` em `load_object`
- **Fallback:** cada feature tem um teste explicito para o caminho de falha (timeout, excecao) garantindo que retorna 0 sem lancar erro

Nenhum teste automatizado depende de conectividade real. O CI (GitHub Actions) pode rodar `pytest tests/` sem configuracao adicional de rede.

## Consequencias

- Suite de testes rapida e deterministsica
- Cobertura explicita do comportamento de fallback
- Mocks precisam ser mantidos alinhados com as assinaturas reais das bibliotecas externas
- Testes de integracao end-to-end com URLs reais ficam como responsabilidade de validacao manual

## Alternativas consideradas

- **Testes contra URLs reais:** cobrem mais cenarios mas sao frageis, lentos e dependem de disponibilidade externa — rejeitado para suite automatizada
- **VCR/cassettes (gravar e reproduzir HTTP):** alternativa valida mas adiciona complexidade de manutencao dos cassettes
