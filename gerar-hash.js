// Importação via padrão ES6 Modules
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import 'dotenv/config'; // Carrega CPF_SECRET_KEY do .env se existir

const saltRounds = 10;
// Chave de 32 bytes para AES-256 (mantenha a mesma no .env do projeto)
const CHAVE_CPF = process.env.CPF_SECRET_KEY || 'clinica_pequenos_passos_32bytes!';
const IV_FIXO = Buffer.alloc(16, 0);

function criptografarCPF(cpf) {
    const cpfLimpo = cpf.replace(/\D/g, '');
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(CHAVE_CPF), IV_FIXO);
    return cipher.update(cpfLimpo, 'utf8', 'hex') + cipher.final('hex');
}

async function gerarDadosBanco() {
    try {
        const usuarios = [
            { nome: 'Ana Clara Souza', cpf: '111.111.111-11', senhaPlana: '123456' },
            { nome: 'Bruno Henrique Lima', cpf: '222.222.222-22', senhaPlana: '123456' },
            { nome: 'Carla Mendes Rocha', cpf: '333.333.333-33', senhaPlana: '123456' }
        ];

        const responsaveis = [
            { nome: 'Mariana Oliveira Santos', cpf: '444.444.444-44' },
            { nome: 'Ricardo Almeida Costa', cpf: '555.555.555-55' },
            { nome: 'Fernanda Silva Pereira', cpf: '666.666.666-66' }
        ];

        console.log('====================================================');
        console.log('USUÁRIOS / OPERADORES (Para tabela usuarios)');
        console.log('====================================================');
        for (const u of usuarios) {
            const hashSenha = await bcrypt.hash(u.senhaPlana, saltRounds);
            const cpfProtegido = criptografarCPF(u.cpf);
            console.log(`Nome: ${u.nome}`);
            console.log(`CPF Original: ${u.cpf} -> cpf_protegido: ${cpfProtegido}`);
            console.log(`Senha Original: ${u.senhaPlana} -> senha_hash: ${hashSenha}`);
            console.log('----------------------------------------------------');
        }

        console.log('\n====================================================');
        console.log('RESPONSÁVEIS (Para tabela responsaveis)');
        console.log('====================================================');
        for (const r of responsaveis) {
            const cpfProtegido = criptografarCPF(r.cpf);
            console.log(`Nome: ${r.nome}`);
            console.log(`CPF Original: ${r.cpf} -> cpf_protegido: ${cpfProtegido}`);
            console.log('----------------------------------------------------');
        }
    } catch (erro) {
        console.error('Erro ao gerar credenciais protegidas:', erro);
    }
}

// Executa o gerador para povoamento do banco
gerarDadosBanco();