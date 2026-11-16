-- ============================================================================
-- SCHEMA: Clínica Pediátrica Pequenos Passos
-- SGBD: PostgreSQL
-- ============================================================================

-- 1. Tabela de Usuários / Operadores (RF01, RF02, RF09)
-- cpf_hash: armazena o CPF protegido para busca/login único sem expor o dado puro.
-- senha_hash: armazena o hash bcrypt da senha.
CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    cpf_protegido VARCHAR(255) UNIQUE NOT NULL,
    senha_hash VARCHAR(255) NOT NULL
);

-- 2. Tabela de Responsáveis (RF03, RF04)
CREATE TABLE IF NOT EXISTS responsaveis (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(120) NOT NULL,
    cpf_protegido VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    telefone VARCHAR(20) NOT NULL
);

-- 3. Tabela de Crianças (RF05)
-- ON DELETE RESTRICT impede a exclusão de um responsável que possua crianças vinculadas,
-- garantindo a integridade referencial exigida nos requisitos.
CREATE TABLE IF NOT EXISTS criancas (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(120) NOT NULL,
    data_nascimento DATE NOT NULL,
    responsavel_id INTEGER NOT NULL REFERENCES responsaveis(id) ON DELETE RESTRICT
);

-- 4. Tabela de Atendimentos (RF06, RF07, RF08)
-- ON DELETE RESTRICT impede excluir uma criança que já tenha atendimentos registrados.
CREATE TABLE IF NOT EXISTS atendimentos (
    id SERIAL PRIMARY KEY,
    crianca_id INTEGER NOT NULL REFERENCES criancas(id) ON DELETE RESTRICT,
    data_atendimento DATE NOT NULL,
    horario TIME NOT NULL,
    motivo VARCHAR(255) NOT NULL,
    situacao VARCHAR(30) NOT NULL DEFAULT 'Agendado'
        CHECK (situacao IN ('Agendado', 'Em Atendimento', 'Concluído', 'Cancelado'))
);

-- Índices auxiliares para otimizar buscas por nome (RF04) e ordenação cronológica (RF08)
CREATE INDEX IF NOT EXISTS idx_responsaveis_nome ON responsaveis (nome);
CREATE INDEX IF NOT EXISTS idx_atendimentos_cronologico ON atendimentos (data_atendimento ASC, horario ASC);

-- ============================================================================
-- POVOAMENTO INICIAL (Mínimo de 3 registros fictícios por tabela - Idempotente)
-- ============================================================================

-- 5. Inserção de Usuários/Operadores
-- Senha fictícia de exemplo para os hashes abaixo: "Senha@123" (gerada com bcrypt)
INSERT INTO usuarios (nome, cpf_protegido, senha_hash) VALUES
('Ana Clara Souza', 'enc_cpf_11111111111', '$2b$10$xCpxxJePzgUFI2hy27EHku7CN49Qaf.iO4d.oTL/OgEX4JnPoHKtK'),
('Bruno Henrique Lima', 'enc_cpf_22222222222', '$2b$10$xCpxxJePzgUFI2hy27EHku7CN49Qaf.iO4d.oTL/OgEX4JnPoHKtK'),
('Carla Mendes Rocha', 'enc_cpf_33333333333', '$2b$10$xCpxxJePzgUFI2hy27EHku7CN49Qaf.iO4d.oTL/OgEX4JnPoHKtK')
ON CONFLICT (cpf_protegido) DO NOTHING;

-- 6. Inserção de Responsáveis
INSERT INTO responsaveis (nome, cpf_protegido, email, telefone) VALUES
('Mariana Oliveira Santos', 'enc_cpf_44444444444', 'mariana.santos@exemplo.com', '(11) 98765-4321'),
('Ricardo Almeida Costa', 'enc_cpf_55555555555', 'ricardo.costa@exemplo.com', '(11) 97654-3210'),
('Fernanda Silva Pereira', 'enc_cpf_66666666666', 'fernanda.pereira@exemplo.com', '(11) 96543-2109')
ON CONFLICT (cpf_protegido) DO NOTHING;

-- 7. Inserção de Crianças (buscando o ID real do responsável dinamicamente)
INSERT INTO criancas (nome, data_nascimento, responsavel_id)
SELECT 'Lucas Oliveira Santos', '2020-05-14', id FROM responsaveis
WHERE cpf_protegido = 'enc_cpf_44444444444'
AND NOT EXISTS (SELECT 1 FROM criancas WHERE nome = 'Lucas Oliveira Santos');

INSERT INTO criancas (nome, data_nascimento, responsavel_id)
SELECT 'Sofia Almeida Costa', '2022-09-22', id FROM responsaveis
WHERE cpf_protegido = 'enc_cpf_55555555555'
AND NOT EXISTS (SELECT 1 FROM criancas WHERE nome = 'Sofia Almeida Costa');

INSERT INTO criancas (nome, data_nascimento, responsavel_id)
SELECT 'Gabriel Silva Pereira', '2019-02-10', id FROM responsaveis
WHERE cpf_protegido = 'enc_cpf_66666666666'
AND NOT EXISTS (SELECT 1 FROM criancas WHERE nome = 'Gabriel Silva Pereira');

-- 8. Inserção de Atendimentos (buscando o ID real da criança dinamicamente)
INSERT INTO atendimentos (crianca_id, data_atendimento, horario, motivo, situacao)
SELECT id, '2026-11-18', '09:00:00', 'Consulta de rotina e acompanhamento de crescimento', 'Agendado'
FROM criancas
WHERE nome = 'Lucas Oliveira Santos'
AND NOT EXISTS (
    SELECT 1 FROM atendimentos a
    WHERE a.crianca_id = criancas.id AND a.data_atendimento = '2026-11-18' AND a.horario = '09:00:00'
);

INSERT INTO atendimentos (crianca_id, data_atendimento, horario, motivo, situacao)
SELECT id, '2026-11-18', '10:30:00', 'Avaliação de quadro gripal e febre', 'Agendado'
FROM criancas
WHERE nome = 'Sofia Almeida Costa'
AND NOT EXISTS (
    SELECT 1 FROM atendimentos a
    WHERE a.crianca_id = criancas.id AND a.data_atendimento = '2026-11-18' AND a.horario = '10:30:00'
);

INSERT INTO atendimentos (crianca_id, data_atendimento, horario, motivo, situacao)
SELECT id, '2026-11-19', '14:15:00', 'Retorno para análise de exames laboratoriais', 'Concluído'
FROM criancas
WHERE nome = 'Gabriel Silva Pereira'
AND NOT EXISTS (
    SELECT 1 FROM atendimentos a
    WHERE a.crianca_id = criancas.id AND a.data_atendimento = '2026-11-19' AND a.horario = '14:15:00'
);