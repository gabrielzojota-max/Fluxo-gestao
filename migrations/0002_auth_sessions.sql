CREATE TABLE IF NOT EXISTS sessoes (
 id TEXT PRIMARY KEY,
 usuario_id TEXT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE,
 expira_em TEXT NOT NULL,
 criado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 revogada_em TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessoes_usuario ON sessoes(usuario_id);
CREATE INDEX IF NOT EXISTS idx_sessoes_expira ON sessoes(expira_em);
CREATE TABLE IF NOT EXISTS tentativas_login (
 id TEXT PRIMARY KEY,
 chave TEXT NOT NULL,
 ocorreu_em INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tentativas_chave_tempo ON tentativas_login(chave, ocorreu_em);
