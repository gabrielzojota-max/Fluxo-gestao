CREATE TABLE configuracoes_empresa (
 id TEXT PRIMARY KEY CHECK(id='principal'),
 nome_fantasia TEXT NOT NULL DEFAULT '',
 razao_social TEXT NOT NULL DEFAULT '',
 telefone TEXT NOT NULL DEFAULT '',
 whatsapp TEXT NOT NULL DEFAULT '',
 endereco TEXT NOT NULL DEFAULT '',
 numero TEXT NOT NULL DEFAULT '',
 complemento TEXT NOT NULL DEFAULT '',
 bairro TEXT NOT NULL DEFAULT '',
 cidade TEXT NOT NULL DEFAULT '',
 cep TEXT NOT NULL DEFAULT '',
 instagram TEXT NOT NULL DEFAULT '',
 facebook TEXT NOT NULL DEFAULT '',
 tiktok TEXT NOT NULL DEFAULT '',
 logo_url TEXT NOT NULL DEFAULT '',
 atualizado_por TEXT REFERENCES usuarios(id),
 atualizado_em TEXT NOT NULL DEFAULT (datetime('now','-3 hours'))
);
