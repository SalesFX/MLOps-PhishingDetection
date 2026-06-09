# ADR-004 — Interface web com chamada assincrona via fetch

**Status:** aceito
**Data:** 2026-06-09

---

## Contexto

A extracao de features de uma URL pode levar entre 3 e 15 segundos por conta de requisicoes HTTP, DNS e WHOIS. Uma chamada sincrona deixaria a pagina travada sem feedback ao usuario, o que seria uma experiencia ruim, especialmente para um portfolio.

## Decisao

Implementar a interface web com:

- Pagina HTML servida pelo FastAPI via Jinja2 (infraestrutura ja existente no projeto)
- JavaScript vanilla com `fetch` para chamar `POST /predict-url` de forma assincrona
- Estado de loading visivel enquanto a analise ocorre ("Analisando URL...")
- Badge com cor E texto descritivo no resultado: vermelho + "PHISHING — Alto risco" para phishing, verde + "LEGITIMA — Baixo risco" para legitima. O resultado nunca depende apenas da cor para ser compreendido.
- Historico das ultimas predicoes armazenado em memoria no JavaScript da sessao (sem backend adicional)
- Bloco colapsavel com as 30 features calculadas e seus valores

Nao sera usado nenhum framework JavaScript (React, Vue, etc.) — apenas HTML + CSS + JS vanilla para manter o projeto simples e sem build step adicional.

## Consequencias

- Experiencia de usuario adequada para um portfolio demonstravel
- Zero dependencias de frontend build — templates Jinja2 servidos diretamente pelo FastAPI
- Historico de sessao perdido ao recarregar a pagina (comportamento aceito para este escopo)
- Interface responsiva basica sem necessidade de framework CSS externo

## Alternativas consideradas

- **Formulario HTML sincrono (POST tradicional):** simples mas trava a pagina durante analise — rejeitado
- **React/Vue SPA:** melhor UX mas adiciona build pipeline, complexidade e foge do escopo MLOps do portfolio
