# ADR-001 — Endpoint separado para predicao por URL bruta

**Status:** aceito
**Data:** 2026-06-09

---

## Contexto

O endpoint atual `POST /predict` aceita um CSV com 30 features numericas pre-extraidas. Para aceitar uma URL bruta e necessario introduzir extracao automatica de features, o que muda completamente o contrato de entrada. Misturar os dois contratos no mesmo endpoint geraria ambiguidade e quebraria clientes existentes.

## Decisao

Criar um novo endpoint `POST /predict-url` que recebe `{ "url": "..." }` e retorna JSON com predicao, confianca, features calculadas e warnings. O endpoint `POST /predict` permanece intocado.

## Consequencias

- Clientes existentes que usam `/predict` nao sao afetados
- Responsabilidades separadas: `/predict` e puramente inferencia, `/predict-url` orquestra extracao + inferencia
- Dois endpoints para manter, mas com contratos claros e independentes

## Alternativas consideradas

- **Estender `/predict`:** aceitar tanto CSV quanto URL no mesmo endpoint. Rejeitado por misturar responsabilidades e complicar testes.
- **Substituir `/predict`:** migrar para apenas URL. Rejeitado por quebrar compatibilidade com o fluxo de treinamento/batch.
