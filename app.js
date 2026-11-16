import express from 'express';
import session from 'express-session';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import 'dotenv/config';
import pool from './db.js';
import { verificarAutenticacao } from './middleware/auth.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Configuração do motor de visualização EJS e arquivos estáticos
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// ==========================================
// CONFIGURAÇÃO DE SESSÃO (RF09)
// ==========================================
app.use(session({
    secret: process.env.SESSION_SECRET || 'clinica-pequenos-passos-sessao-local',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 30, // Expira em 30 minutos
        httpOnly: true,
        sameSite: 'lax'
    }
}));

// ==========================================
// FUNÇÕES DE PROTEÇÃO DE CPF E VALIDAÇÕES
// ==========================================
const CHAVE_CPF = process.env.CPF_SECRET_KEY || 'clinica_pequenos_passos_32bytes!';
const IV_FIXO = Buffer.alloc(16, 0);

function criptografarCPF(cpf) {
    const cpfLimpo = String(cpf).replace(/\D/g, '');
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(CHAVE_CPF), IV_FIXO);
    return cipher.update(cpfLimpo, 'utf8', 'hex') + cipher.final('hex');
}

function descriptografarCPF(cpfProtegido) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(CHAVE_CPF), IV_FIXO);
    const limpo = decipher.update(cpfProtegido, 'hex', 'utf8') + decipher.final('utf8');
    return limpo.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
}

function cpfValido(cpf) {
    return String(cpf || '').replace(/\D/g, '').length === 11;
}

// ==========================================
// ROTAS DE AUTENTICAÇÃO E HOME (RF01, RF02, RF09)
// ==========================================
app.get('/login', (req, res) => {
    if (req.session.usuario) return res.redirect('/');
    res.render('login', { erro: null });
});

app.post('/login', async (req, res) => {
    const { cpf, senha } = req.body;
    if (typeof cpf !== 'string' || typeof senha !== 'string' || !cpfValido(cpf) || !senha.trim()) {
        return res.status(400).render('login', { erro: 'CPF ou senha inválidos.' });
    }

    try {
        const cpfProtegido = criptografarCPF(cpf);
        const resultado = await pool.query(
            'SELECT id, nome, senha_hash FROM usuarios WHERE cpf_protegido = $1',
            [cpfProtegido]
        );

        if (resultado.rows.length === 0) {
            return res.status(401).render('login', { erro: 'CPF ou senha inválidos.' });
        }

        const usuario = resultado.rows[0];
        const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);

        if (!senhaValida) {
            return res.status(401).render('login', { erro: 'CPF ou senha inválidos.' });
        }

        req.session.regenerate((erroSessao) => {
            if (erroSessao) return res.status(500).send('Falha ao iniciar sessão.');
            req.session.usuario = {
                id: usuario.id,
                nome: usuario.nome
            };
            req.session.save((erroSalvar) => {
                if (erroSalvar) return res.status(500).send('Falha ao salvar sessão.');
                res.redirect('/');
            });
        });
    } catch (err) {
        console.error(err);
        res.status(500).render('login', { erro: 'Erro interno ao realizar login.' });
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy((erro) => {
        if (erro) return res.status(500).send('Erro ao encerrar sessão.');
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// Página Inicial (RF02)
app.get('/', verificarAutenticacao, (req, res) => {
    res.render('index', { usuario: req.session.usuario });
});

// ==========================================
// CRUD DE RESPONSÁVEIS + BUSCA (RF03, RF04)
// ==========================================
app.get('/responsaveis', verificarAutenticacao, async (req, res) => {
    const busca = (req.query.busca || '').trim();
    const erro = req.query.erro || null;

    try {
        let querySql = 'SELECT id, nome, cpf_protegido, email, telefone FROM responsaveis ORDER BY nome ASC';
        let params = [];

        if (busca) {
            querySql = 'SELECT id, nome, cpf_protegido, email, telefone FROM responsaveis WHERE nome ILIKE $1 ORDER BY nome ASC';
            params = [`%${busca}%`];
        }

        const resultado = await pool.query(querySql, params);
        const responsaveis = resultado.rows.map((r) => ({
            ...r,
            cpf: descriptografarCPF(r.cpf_protegido)
        }));

        res.render('responsaveis', {
            responsaveis,
            usuario: req.session.usuario,
            busca,
            erro
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao buscar responsáveis.');
    }
});

app.get('/responsaveis/novo', verificarAutenticacao, (req, res) => {
    res.render('novo-responsavel', { usuario: req.session.usuario, erro: null });
});

app.post('/responsaveis/novo', verificarAutenticacao, async (req, res) => {
    const { nome, cpf, email, telefone } = req.body;

    if (!nome?.trim() || !cpfValido(cpf) || !email?.trim() || !telefone?.trim()) {
        return res.status(400).render('novo-responsavel', {
            usuario: req.session.usuario,
            erro: 'Preencha todos os campos corretamente (CPF deve ter 11 dígitos).'
        });
    }

    try {
        const cpfProtegido = criptografarCPF(cpf);
        await pool.query(
            'INSERT INTO responsaveis (nome, cpf_protegido, email, telefone) VALUES ($1, $2, $3, $4)',
            [nome.trim(), cpfProtegido, email.trim(), telefone.trim()]
        );
        res.redirect('/responsaveis');
    } catch (err) {
        console.error(err);
        if (err.code === '23505') {
            return res.status(400).render('novo-responsavel', {
                usuario: req.session.usuario,
                erro: 'CPF ou e-mail já cadastrado para outro responsável.'
            });
        }
        res.status(500).send('Erro ao cadastrar responsável.');
    }
});

app.get('/responsaveis/editar/:id', verificarAutenticacao, async (req, res) => {
    try {
        const resultado = await pool.query('SELECT * FROM responsaveis WHERE id = $1', [req.params.id]);
        if (resultado.rows.length === 0) return res.status(404).send('Responsável não encontrado.');

        const resp = resultado.rows[0];
        resp.cpf = descriptografarCPF(resp.cpf_protegido);

        res.render('editar-responsavel', {
            responsavel: resp,
            usuario: req.session.usuario,
            erro: null
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao carregar responsável.');
    }
});

app.post('/responsaveis/editar/:id', verificarAutenticacao, async (req, res) => {
    const { id } = req.params;
    const { nome, cpf, email, telefone } = req.body;

    if (!nome?.trim() || !cpfValido(cpf) || !email?.trim() || !telefone?.trim()) {
        return res.status(400).send('Todos os campos são obrigatórios e o CPF deve ter 11 dígitos.');
    }

    try {
        const cpfProtegido = criptografarCPF(cpf);
        await pool.query(
            'UPDATE responsaveis SET nome = $1, cpf_protegido = $2, email = $3, telefone = $4 WHERE id = $5',
            [nome.trim(), cpfProtegido, email.trim(), telefone.trim(), id]
        );
        res.redirect('/responsaveis');
    } catch (err) {
        console.error(err);
        if (err.code === '23505') {
            return res.status(400).send('CPF ou e-mail já está em uso por outro responsável.');
        }
        res.status(500).send('Erro ao atualizar responsável.');
    }
});

app.post('/responsaveis/deletar/:id', verificarAutenticacao, async (req, res) => {
    try {
        await pool.query('DELETE FROM responsaveis WHERE id = $1', [req.params.id]);
        res.redirect('/responsaveis');
    } catch (err) {
        console.error(err);
        // Código 23503 = violação de chave estrangeira (responsável possui crianças vinculadas)
        if (err.code === '23503') {
            return res.redirect('/responsaveis?erro=' + encodeURIComponent('Não é possível excluir este responsável pois existem crianças vinculadas a ele.'));
        }
        res.status(500).send('Erro ao excluir responsável.');
    }
});

// ==========================================
// CRUD DE CRIANÇAS (RF05)
// ==========================================
app.get('/criancas', verificarAutenticacao, async (req, res) => {
    const erro = req.query.erro || null;
    try {
        const resultado = await pool.query(`
            SELECT c.id, c.nome, c.data_nascimento, c.responsavel_id, r.nome AS nome_responsavel
            FROM criancas c
            INNER JOIN responsaveis r ON c.responsavel_id = r.id
            ORDER BY c.nome ASC
        `);
        res.render('criancas', {
            criancas: resultado.rows,
            usuario: req.session.usuario,
            erro
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao listar crianças.');
    }
});

app.get('/criancas/novo', verificarAutenticacao, async (req, res) => {
    try {
        const responsaveisRes = await pool.query('SELECT id, nome FROM responsaveis ORDER BY nome ASC');
        res.render('nova-crianca', {
            responsaveis: responsaveisRes.rows,
            usuario: req.session.usuario,
            erro: null
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao carregar formulário de criança.');
    }
});

app.post('/criancas/novo', verificarAutenticacao, async (req, res) => {
    const { nome, data_nascimento, responsavel_id } = req.body;
    const idResp = Number(responsavel_id);

    if (!nome?.trim() || !data_nascimento || !Number.isInteger(idResp) || idResp <= 0) {
        return res.status(400).send('Nome, data de nascimento e responsável são obrigatórios.');
    }

    try {
        // Verifica se o responsável existe no banco antes de inserir
        const respExiste = await pool.query('SELECT id FROM responsaveis WHERE id = $1', [idResp]);
        if (respExiste.rows.length === 0) {
            return res.status(400).send('O responsável selecionado não existe.');
        }

        await pool.query(
            'INSERT INTO criancas (nome, data_nascimento, responsavel_id) VALUES ($1, $2, $3)',
            [nome.trim(), data_nascimento, idResp]
        );
        res.redirect('/criancas');
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao cadastrar criança.');
    }
});

app.get('/criancas/editar/:id', verificarAutenticacao, async (req, res) => {
    try {
        const criancaRes = await pool.query('SELECT * FROM criancas WHERE id = $1', [req.params.id]);
        if (criancaRes.rows.length === 0) return res.status(404).send('Criança não encontrada.');

        const responsaveisRes = await pool.query('SELECT id, nome FROM responsaveis ORDER BY nome ASC');
        res.render('editar-crianca', {
            crianca: criancaRes.rows[0],
            responsaveis: responsaveisRes.rows,
            usuario: req.session.usuario
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao carregar dados da criança.');
    }
});

app.post('/criancas/editar/:id', verificarAutenticacao, async (req, res) => {
    const { id } = req.params;
    const { nome, data_nascimento, responsavel_id } = req.body;
    const idResp = Number(responsavel_id);

    if (!nome?.trim() || !data_nascimento || !Number.isInteger(idResp) || idResp <= 0) {
        return res.status(400).send('Todos os campos são obrigatórios.');
    }

    try {
        const respExiste = await pool.query('SELECT id FROM responsaveis WHERE id = $1', [idResp]);
        if (respExiste.rows.length === 0) {
            return res.status(400).send('Responsável inválido.');
        }

        await pool.query(
            'UPDATE criancas SET nome = $1, data_nascimento = $2, responsavel_id = $3 WHERE id = $4',
            [nome.trim(), data_nascimento, idResp, id]
        );
        res.redirect('/criancas');
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao atualizar criança.');
    }
});

app.post('/criancas/deletar/:id', verificarAutenticacao, async (req, res) => {
    try {
        await pool.query('DELETE FROM criancas WHERE id = $1', [req.params.id]);
        res.redirect('/criancas');
    } catch (err) {
        console.error(err);
        if (err.code === '23503') {
            return res.redirect('/criancas?erro=' + encodeURIComponent('Não é possível excluir esta criança pois ela possui atendimentos registrados.'));
        }
        res.status(500).send('Erro ao excluir criança.');
    }
});

// ==========================================
// CRUD DE ATENDIMENTOS + JOIN + ORDENAÇÃO (RF06, RF07, RF08)
// ==========================================
app.get('/atendimentos', verificarAutenticacao, async (req, res) => {
    try {
        const resultado = await pool.query(`
            SELECT 
                a.id,
                a.data_atendimento,
                a.horario,
                a.motivo,
                a.situacao,
                c.nome AS nome_crianca,
                r.nome AS nome_responsavel
            FROM atendimentos a
            INNER JOIN criancas c ON a.crianca_id = c.id
            INNER JOIN responsaveis r ON c.responsavel_id = r.id
            ORDER BY a.data_atendimento ASC, a.horario ASC
        `);

        res.render('atendimentos', {
            atendimentos: resultado.rows,
            usuario: req.session.usuario
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao listar atendimentos.');
    }
});

app.get('/atendimentos/novo', verificarAutenticacao, async (req, res) => {
    try {
        const criancasRes = await pool.query(`
            SELECT c.id, c.nome, r.nome AS nome_responsavel
            FROM criancas c
            INNER JOIN responsaveis r ON c.responsavel_id = r.id
            ORDER BY c.nome ASC
        `);
        res.render('novo-atendimento', {
            criancas: criancasRes.rows,
            usuario: req.session.usuario
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao carregar formulário de atendimento.');
    }
});

app.post('/atendimentos/novo', verificarAutenticacao, async (req, res) => {
    const { crianca_id, data_atendimento, horario, motivo, situacao } = req.body;
    const idCrianca = Number(crianca_id);
    const situacoesPermitidas = ['Agendado', 'Em Atendimento', 'Concluído', 'Cancelado'];

    if (!Number.isInteger(idCrianca) || idCrianca <= 0 || !data_atendimento || !horario || !motivo?.trim() || !situacoesPermitidas.includes(situacao)) {
        return res.status(400).send('Preencha todos os campos do atendimento corretamente.');
    }

    try {
        const criancaExiste = await pool.query('SELECT id FROM criancas WHERE id = $1', [idCrianca]);
        if (criancaExiste.rows.length === 0) {
            return res.status(400).send('A criança selecionada não existe.');
        }

        await pool.query(
            'INSERT INTO atendimentos (crianca_id, data_atendimento, horario, motivo, situacao) VALUES ($1, $2, $3, $4, $5)',
            [idCrianca, data_atendimento, horario, motivo.trim(), situacao]
        );
        res.redirect('/atendimentos');
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao registrar atendimento.');
    }
});

app.get('/atendimentos/editar/:id', verificarAutenticacao, async (req, res) => {
    try {
        const atendimentoRes = await pool.query('SELECT * FROM atendimentos WHERE id = $1', [req.params.id]);
        if (atendimentoRes.rows.length === 0) return res.status(404).send('Atendimento não encontrado.');

        const criancasRes = await pool.query(`
            SELECT c.id, c.nome, r.nome AS nome_responsavel
            FROM criancas c
            INNER JOIN responsaveis r ON c.responsavel_id = r.id
            ORDER BY c.nome ASC
        `);

        res.render('editar-atendimento', {
            atendimento: atendimentoRes.rows[0],
            criancas: criancasRes.rows,
            usuario: req.session.usuario
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao carregar atendimento.');
    }
});

app.post('/atendimentos/editar/:id', verificarAutenticacao, async (req, res) => {
    const { id } = req.params;
    const { crianca_id, data_atendimento, horario, motivo, situacao } = req.body;
    const idCrianca = Number(crianca_id);
    const situacoesPermitidas = ['Agendado', 'Em Atendimento', 'Concluído', 'Cancelado'];

    if (!Number.isInteger(idCrianca) || idCrianca <= 0 || !data_atendimento || !horario || !motivo?.trim() || !situacoesPermitidas.includes(situacao)) {
        return res.status(400).send('Dados inválidos para atualização do atendimento.');
    }

    try {
        const criancaExiste = await pool.query('SELECT id FROM criancas WHERE id = $1', [idCrianca]);
        if (criancaExiste.rows.length === 0) {
            return res.status(400).send('Criança inválida.');
        }

        await pool.query(
            'UPDATE atendimentos SET crianca_id = $1, data_atendimento = $2, horario = $3, motivo = $4, situacao = $5 WHERE id = $6',
            [idCrianca, data_atendimento, horario, motivo.trim(), situacao, id]
        );
        res.redirect('/atendimentos');
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao atualizar atendimento.');
    }
});

app.post('/atendimentos/deletar/:id', verificarAutenticacao, async (req, res) => {
    try {
        await pool.query('DELETE FROM atendimentos WHERE id = $1', [req.params.id]);
        res.redirect('/atendimentos');
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao excluir atendimento.');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor da Clínica Pequenos Passos rodando em http://localhost:${PORT}`);
});