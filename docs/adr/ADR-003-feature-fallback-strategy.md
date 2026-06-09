# ADR-003 — Estrategia de fallback para features nao calculaveis

**Status:** aceito
**Data:** 2026-06-09

---

## Contexto

Das 30 features, aproximadamente 5 dependem de APIs externas extintas ou pagas (Alexa/web_traffic, Google PageRank, Google Index, links apontando para a pagina). Outras podem falhar por timeout, URL alvo fora do ar ou WHOIS indisponivel. Deixar a predicao falhar por causa de um servico externo e inaceitavel.

## Decisao

Usar abordagem configuravel em tres niveis:

1. **Tentativa com alternativa gratuita:** para features com substituto viavel (ex: Tranco para web_traffic, PhishTank API para statistical_report), tenta buscar o valor real
2. **Fallback neutro (0):** se a tentativa falhar por qualquer motivo (timeout, erro HTTP, API indisponivel), usa valor 0
3. **Warning no response:** toda feature que usou fallback e listada no campo `warnings` do JSON de resposta — nunca silencioso

O valor 0 foi escolhido como neutro por nao ser nem -1 (legitimo) nem 1 (phishing) nas features binarias do dataset UCI.

## Consequencias

- A predicao nunca quebra por causa de servico externo
- O consumidor da API sabe quais features usaram fallback via `warnings`
- Leve impacto na precisao quando muitas features caem em fallback, documentado nas limitacoes
- Features de APIs mortas (PageRank, Google Index) usam fallback permanentemente ate que uma alternativa seja integrada

## Alternativas consideradas

- **Retornar erro se features criticas falharem:** garantiria qualidade maxima mas tornaria a API fragil para URLs em dominios lentos ou fora do ar
- **Omitir features sem valor:** quebraria o vetor de entrada do modelo que espera exatamente 30 features na ordem correta
