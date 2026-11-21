ALTER TABLE despesas ADD COLUMN origem_recurso TEXT NOT NULL DEFAULT 'empresa' CHECK(origem_recurso IN ('empresa','pessoal'));
