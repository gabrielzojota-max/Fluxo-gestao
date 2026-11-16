# API do FLUXO GESTÃO

Worker publicado como `fluxo-gestao-api`, com binding D1 `DB` apontando para o banco `fluxo-gestao`.

## Endpoint de diagnóstico
- `GET /api/health`: executa uma consulta simples no D1 e informa se a conexão está ativa e quantas tabelas da aplicação existem.
- Não retorna dados de clientes, pagamentos ou usuários.

O Worker ainda não contém autenticação nem endpoints de negócio. Não adicionar operações com dados reais antes de implementar sessão, autorização por papel/permissão, validação de entrada e auditoria.
