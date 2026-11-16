# FLUXO GESTÃO
Sistema de gestão da FLUXO Estética Automotiva.

## Stack
- React + TypeScript + Vite (interface)
- Cloudflare D1 (dados)
- Cloudflare Workers (API e validações)
- Cloudflare R2 (arquivos privados e backups, integração futura)

## Regras
- Projeto separado do REC Cidade Grande.
- pt-BR, BRL, America/Sao_Paulo.
- Login por e-mail e senha; sem Google OAuth.
- Senhas somente com hash seguro; nunca texto puro.
- Não versionar segredos, tokens ou dados reais.
- Não declarar recursos prontos sem testes.

## Rodar localmente
`npm install` e `npm run dev`.

A migration inicial está em `migrations/0001_initial.sql`. Ela já foi aplicada no banco D1 existente.