ALTER TABLE pagamentos ADD COLUMN taxa_centavos INTEGER NOT NULL DEFAULT 0;
ALTER TABLE pagamentos ADD COLUMN liquido_centavos INTEGER;
UPDATE pagamentos SET liquido_centavos=valor_centavos WHERE liquido_centavos IS NULL;
