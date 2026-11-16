// Middleware de verificação de sessão
export function verificarAutenticacao(req, res, next) {
    if (req.session && req.session.usuario) {
        res.locals.usuario = req.session.usuario;
        return next();
    }

    return res.redirect('/login');
}