
import express from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import 'dotenv/config';
import pool from './db.js';
import { verificarAutenticacao } from './middleware/auth.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Configuração do EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// Configuração de sessão
app.use(session({
    secret: process.env.SESSION_SECRET || 'clinica-pequenos-passos-local',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 30,
        httpOnly: true,
        sameSite: 'lax'
    }
}));

// Proteção do CPF
const CHAVE_CPF = process.env.CPF_SECRET_KEY || '12345678901234567890123456789012';
const IV_FIXO = Buffer.alloc(16, 0);

function criptografarCPF(cpf) {
    const cpfLimpo = String(cpf).replace(/\D/g, '');
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(CHAVE_CPF), IV_FIXO);

    return cipher.update(cpfLimpo, 'utf8', 'hex') + cipher.final('hex');
}

function descriptografarCPF(cpfProtegido) {
    if (cpfProtegido.startsWith('enc_cpf_')) {
        const cpf = cpfProtegido.replace('enc_cpf_', '');
        return cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
    }

    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(CHAVE_CPF), IV_FIXO);
    const cpf = decipher.update(cpfProtegido, 'hex', 'utf8') + decipher.final('utf8');

    return cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
}

function cpfValido(cpf) {
    return String(cpf || '').replace(/\D/g, '').length === 11;
}

const situacoesPermitidas = ['Agendado', 'Em Atendimento', 'Concluído', 'Cancelado'];

// Login
app.get('/login', (req, res) => {
    if (req.session.usuario) return res.redirect('/');
    res.render('login', { erro: null });
});

app.post('/login', async (req, res) => {
    const { cpf, senha } = req.body;

    if (!cpfValido(cpf) || !senha?.trim()) {
        return res.status(400).render('login', { erro: 'CPF ou senha inválidos.' });
    }

    try {
        const cpfLimpo = cpf.replace(/\D/g, '');
        const cpfProtegido = criptografarCPF(cpfLimpo);
        const cpfAntigo = `enc_cpf_${cpfLimpo}`;

        const resultado = await pool.query(
            `SELECT id, nome, senha_hash
             FROM usuarios
             WHERE cpf_protegido = $1 OR cpf_protegido = $2
             LIMIT 1`,
            [cpfProtegido, cpfAntigo]
        );

        if (resultado.rows.length === 0) {
            return res.status(401).render('login', { erro: 'CPF ou senha inválidos.' });
        }

        const usuario = resultado.rows[0];
        const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);

        if (!senhaValida) {
            return res.status(401).render('login', { erro: 'CPF ou senha inválidos.' });
        }

        req.session.regenerate((erro) => {
            if (erro) return res.status(500).send('Erro ao iniciar sessão.');

            req.session.usuario = {
                id: usuario.id,
                nome: usuario.nome
            };

            req.session.save((erroSalvar) => {
                if (erroSalvar) return res.status(500).send('Erro ao salvar sessão.');
                res.redirect('/');
            });
        });
    } catch (erro) {
        console.error(erro);
        res.status(500).render('login', { erro: 'Erro interno ao realizar login.' });
    }
});

// Logout
app.post('/logout', (req, res) => {
    req.session.destroy((erro) => {
        if (erro) return res.status(500).send('Erro ao encerrar sessão.');

        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// Página inicial
app.get('/', verificarAutenticacao, (req, res) => {
    res.render('home', { usuario: req.session.usuario });
});

// CRUD de responsáveis
app.get('/responsaveis', verificarAutenticacao, async (req, res) => {
    const busca = (req.query.busca || '').trim();

    try {
        let sql = `SELECT id, nome, cpf_protegido, email, telefone FROM responsaveis`;
        let parametros = [];

        if (busca) {
            sql += ` WHERE nome ILIKE $1`;
            parametros.push(`%${busca}%`);
        }

        sql += ` ORDER BY nome ASC`;

        const resultado = await pool.query(sql, parametros);

        const responsaveis = resultado.rows.map((r) => ({
            ...r,
            cpf: descriptografarCPF(r.cpf_protegido)
        }));

        res.render('responsaveis', {
            responsaveis,
            busca,
            erro: req.query.erro || null
        });
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao listar responsáveis.');
    }
});

app.get('/responsaveis/novo', verificarAutenticacao, (req, res) => {
    res.render('novo-responsavel', { erro: null });
});

app.post('/responsaveis/novo', verificarAutenticacao, async (req, res) => {
    const { nome, cpf, email, telefone } = req.body;

    if (!nome?.trim() || !cpfValido(cpf) || !email?.trim() || !telefone?.trim()) {
        return res.status(400).render('novo-responsavel', {
            erro: 'Preencha todos os campos corretamente.'
        });
    }

    try {
        await pool.query(
            `INSERT INTO responsaveis (nome, cpf_protegido, email, telefone)
             VALUES ($1, $2, $3, $4)`,
            [nome.trim(), criptografarCPF(cpf), email.trim(), telefone.trim()]
        );

        res.redirect('/responsaveis');
    } catch (erro) {
        console.error(erro);

        if (erro.code === '23505') {
            return res.status(400).render('novo-responsavel', {
                erro: 'CPF ou e-mail já cadastrado.'
            });
        }

        res.status(500).send('Erro ao cadastrar responsável.');
    }
});

app.get('/responsaveis/editar/:id', verificarAutenticacao, async (req, res) => {
    try {
        const resultado = await pool.query(
            'SELECT * FROM responsaveis WHERE id = $1',
            [req.params.id]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).send('Responsável não encontrado.');
        }

        const responsavel = resultado.rows[0];
        responsavel.cpf = descriptografarCPF(responsavel.cpf_protegido);

        res.render('editar-responsavel', { responsavel, erro: null });
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao carregar responsável.');
    }
});

app.post('/responsaveis/editar/:id', verificarAutenticacao, async (req, res) => {
    const { nome, cpf, email, telefone } = req.body;

    if (!nome?.trim() || !cpfValido(cpf) || !email?.trim() || !telefone?.trim()) {
        return res.status(400).send('Preencha todos os campos corretamente.');
    }

    try {
        await pool.query(
            `UPDATE responsaveis
             SET nome = $1, cpf_protegido = $2, email = $3, telefone = $4
             WHERE id = $5`,
            [nome.trim(), criptografarCPF(cpf), email.trim(), telefone.trim(), req.params.id]
        );

        res.redirect('/responsaveis');
    } catch (erro) {
        console.error(erro);

        if (erro.code === '23505') {
            return res.status(400).send('CPF ou e-mail já cadastrado.');
        }

        res.status(500).send('Erro ao atualizar responsável.');
    }
});

app.post('/responsaveis/deletar/:id', verificarAutenticacao, async (req, res) => {
    try {
        await pool.query('DELETE FROM responsaveis WHERE id = $1', [req.params.id]);
        res.redirect('/responsaveis');
    } catch (erro) {
        console.error(erro);

        if (erro.code === '23503') {
            return res.redirect('/responsaveis?erro=' +
                encodeURIComponent('Este responsável possui crianças vinculadas.'));
        }

        res.status(500).send('Erro ao excluir responsável.');
    }
});

// CRUD de crianças
app.get('/criancas', verificarAutenticacao, async (req, res) => {
    try {
        const resultado = await pool.query(`
            SELECT c.id, c.nome, c.data_nascimento, c.responsavel_id,
                   r.nome AS responsavel
            FROM criancas c
            INNER JOIN responsaveis r ON c.responsavel_id = r.id
            ORDER BY c.nome ASC
        `);

        res.render('criancas', {
            criancas: resultado.rows,
            erro: req.query.erro || null
        });
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao listar crianças.');
    }
});

app.get('/criancas/novo', verificarAutenticacao, async (req, res) => {
    try {
        const resultado = await pool.query(
            'SELECT id, nome FROM responsaveis ORDER BY nome ASC'
        );

        res.render('nova-crianca', {
            responsaveis: resultado.rows,
            erro: null
        });
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao carregar formulário.');
    }
});

app.post('/criancas/novo', verificarAutenticacao, async (req, res) => {
    const { nome, data_nascimento, responsavel_id } = req.body;
    const idResponsavel = Number(responsavel_id);

    if (!nome?.trim() || !data_nascimento ||
        !Number.isInteger(idResponsavel) || idResponsavel <= 0) {
        return res.status(400).send('Preencha todos os campos.');
    }

    try {
        await pool.query(
            `INSERT INTO criancas (nome, data_nascimento, responsavel_id)
             VALUES ($1, $2, $3)`,
            [nome.trim(), data_nascimento, idResponsavel]
        );

        res.redirect('/criancas');
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao cadastrar criança.');
    }
});

app.get('/criancas/editar/:id', verificarAutenticacao, async (req, res) => {
    try {
        const criancaRes = await pool.query(
            'SELECT * FROM criancas WHERE id = $1',
            [req.params.id]
        );

        if (criancaRes.rows.length === 0) {
            return res.status(404).send('Criança não encontrada.');
        }

        const responsaveisRes = await pool.query(
            'SELECT id, nome FROM responsaveis ORDER BY nome ASC'
        );

        res.render('editar-crianca', {
            crianca: criancaRes.rows[0],
            responsaveis: responsaveisRes.rows
        });
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao carregar criança.');
    }
});

app.post('/criancas/editar/:id', verificarAutenticacao, async (req, res) => {
    const { nome, data_nascimento, responsavel_id } = req.body;
    const idResponsavel = Number(responsavel_id);

    if (!nome?.trim() || !data_nascimento ||
        !Number.isInteger(idResponsavel) || idResponsavel <= 0) {
        return res.status(400).send('Preencha todos os campos.');
    }

    try {
        await pool.query(
            `UPDATE criancas
             SET nome = $1, data_nascimento = $2, responsavel_id = $3
             WHERE id = $4`,
            [nome.trim(), data_nascimento, idResponsavel, req.params.id]
        );

        res.redirect('/criancas');
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao atualizar criança.');
    }
});

app.post('/criancas/deletar/:id', verificarAutenticacao, async (req, res) => {
    try {
        await pool.query('DELETE FROM criancas WHERE id = $1', [req.params.id]);
        res.redirect('/criancas');
    } catch (erro) {
        console.error(erro);

        if (erro.code === '23503') {
            return res.redirect('/criancas?erro=' +
                encodeURIComponent('Esta criança possui atendimentos registrados.'));
        }

        res.status(500).send('Erro ao excluir criança.');
    }
});

// CRUD de atendimentos
app.get('/atendimentos', verificarAutenticacao, async (req, res) => {
    try {
        const resultado = await pool.query(`
            SELECT a.id, a.data_atendimento, a.horario, a.motivo, a.situacao,
                   c.nome AS crianca, r.nome AS responsavel
            FROM atendimentos a
            INNER JOIN criancas c ON a.crianca_id = c.id
            INNER JOIN responsaveis r ON c.responsavel_id = r.id
            ORDER BY a.data_atendimento ASC, a.horario ASC
        `);

        res.render('atendimentos', { atendimentos: resultado.rows });
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao listar atendimentos.');
    }
});

app.get('/atendimentos/novo', verificarAutenticacao, async (req, res) => {
    try {
        const resultado = await pool.query(
            'SELECT id, nome FROM criancas ORDER BY nome ASC'
        );

        res.render('novo-atendimento', {
            criancas: resultado.rows,
            erro: null
        });
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao carregar formulário de atendimento.');
    }
});

app.post('/atendimentos/novo', verificarAutenticacao, async (req, res) => {
    const { crianca_id, data_atendimento, horario, motivo, situacao } = req.body;
    const idCrianca = Number(crianca_id);

    if (!Number.isInteger(idCrianca) || idCrianca <= 0 ||
        !data_atendimento || !horario || !motivo?.trim() ||
        !situacoesPermitidas.includes(situacao)) {
        return res.status(400).send('Preencha todos os campos corretamente.');
    }

    try {
        await pool.query(
            `INSERT INTO atendimentos
             (crianca_id, data_atendimento, horario, motivo, situacao)
             VALUES ($1, $2, $3, $4, $5)`,
            [idCrianca, data_atendimento, horario, motivo.trim(), situacao]
        );

        res.redirect('/atendimentos');
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao cadastrar atendimento.');
    }
});

app.get('/atendimentos/editar/:id', verificarAutenticacao, async (req, res) => {
    try {
        const atendimentoRes = await pool.query(
            'SELECT * FROM atendimentos WHERE id = $1',
            [req.params.id]
        );

        if (atendimentoRes.rows.length === 0) {
            return res.status(404).send('Atendimento não encontrado.');
        }

        const criancasRes = await pool.query(
            'SELECT id, nome FROM criancas ORDER BY nome ASC'
        );

        res.render('editar-atendimento', {
            atendimento: atendimentoRes.rows[0],
            criancas: criancasRes.rows
        });
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao carregar atendimento.');
    }
});

app.post('/atendimentos/editar/:id', verificarAutenticacao, async (req, res) => {
    const { crianca_id, data_atendimento, horario, motivo, situacao } = req.body;
    const idCrianca = Number(crianca_id);

    if (!Number.isInteger(idCrianca) || idCrianca <= 0 ||
        !data_atendimento || !horario || !motivo?.trim() ||
        !situacoesPermitidas.includes(situacao)) {
        return res.status(400).send('Preencha todos os campos corretamente.');
    }

    try {
        await pool.query(
            `UPDATE atendimentos
             SET crianca_id = $1, data_atendimento = $2, horario = $3,
                 motivo = $4, situacao = $5
             WHERE id = $6`,
            [idCrianca, data_atendimento, horario, motivo.trim(), situacao, req.params.id]
        );

        res.redirect('/atendimentos');
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao atualizar atendimento.');
    }
});

app.post('/atendimentos/deletar/:id', verificarAutenticacao, async (req, res) => {
    try {
        await pool.query('DELETE FROM atendimentos WHERE id = $1', [req.params.id]);
        res.redirect('/atendimentos');
    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao excluir atendimento.');
    }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Servidor da Clínica Pequenos Passos rodando em http://localhost:${PORT}`);
});
