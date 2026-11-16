
import bcrypt from 'bcryptjs';
import pool from './db.js';

async function atualizarSenha() {
    try {
        const senha = 'Senha@123';
        const senhaHash = await bcrypt.hash(senha, 10);

        const resultado = await pool.query(
            `UPDATE usuarios
             SET senha_hash = $1
             WHERE cpf_protegido = $2`,
            [senhaHash, 'enc_cpf_11111111111']
        );

        if (resultado.rowCount === 0) {
            console.log('Usuário não encontrado no banco de dados.');
        } else {
            console.log('Senha atualizada com sucesso!');
        }

    } catch (erro) {
        console.error('Erro ao atualizar senha:', erro);
    } finally {
        await pool.end();
    }
}

atualizarSenha();
