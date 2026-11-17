ALTER TABLE clientes ADD COLUMN ativo INTEGER NOT NULL DEFAULT 1 CHECK(ativo IN (0,1));
ALTER TABLE clientes ADD COLUMN arquivado_em TEXT;
ALTER TABLE atendimentos ADD COLUMN motivo_cancelamento TEXT;
ALTER TABLE atendimentos ADD COLUMN cancelado_em TEXT;
