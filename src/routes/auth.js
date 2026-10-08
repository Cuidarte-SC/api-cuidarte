// RF-1: autenticación y sesión
const express = require('express');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const config = require('../config');
const db = require('../db');
const { autenticar } = require('../middleware/auth');
const { registrar, ipDe } = require('../services/auditoria');

const router = express.Router();

// Limita intentos de login por IP (fuerza bruta)
const limiteLogin = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Demasiados intentos de inicio de sesión, intente en 15 minutos' },
});

// Hash ficticio para que un usuario inexistente tarde lo mismo que uno real
const HASH_FICTICIO = bcrypt.hashSync('usuario-inexistente-cuidarte', config.bcryptCosto);

router.post('/login', limiteLogin, async (req, res) => {
  const { nombre_usuario: nombreUsuario, password } = req.body || {};

  if (typeof nombreUsuario !== 'string' || typeof password !== 'string' || !nombreUsuario || !password) {
    return res.status(400).json({ error: 'Debe indicar nombre_usuario y password' });
  }

  const { rows } = await db.query(
    'SELECT id, nombre_usuario, nombre, rol, paciente_id, password_hash, activo FROM usuario WHERE nombre_usuario = $1',
    [nombreUsuario],
  );
  const usuario = rows[0];
  const coincide = await bcrypt.compare(password, usuario ? usuario.password_hash : HASH_FICTICIO);

  if (!usuario || !usuario.activo || !coincide) {
    await registrar({
      usuarioId: usuario ? usuario.id : null,
      accion: 'LOGIN_FALLIDO',
      descripcion: 'Credenciales inválidas', // nunca se registra la contraseña
      ip: ipDe(req),
    });
    // Mensaje genérico: no revela si el usuario existe
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  const jti = crypto.randomUUID();
  const token = jwt.sign({ rol: usuario.rol }, config.jwt.secreto, {
    algorithm: config.jwt.algoritmo,
    expiresIn: config.jwt.expiraEn,
    subject: String(usuario.id),
    jwtid: jti,
  });
  const { exp } = jwt.decode(token);

  await registrar({ usuarioId: usuario.id, accion: 'LOGIN', ip: ipDe(req) });

  return res.status(200).json({
    token,
    tipo: 'Bearer',
    expira_en: new Date(exp * 1000).toISOString(),
    usuario: {
      id: usuario.id,
      nombre_usuario: usuario.nombre_usuario,
      nombre: usuario.nombre,
      rol: usuario.rol,
      paciente_id: usuario.paciente_id,
    },
  });
});

// Logout: revoca el token actual (queda inutilizable aunque no haya expirado)
router.post('/logout', autenticar, async (req, res) => {
  await db.query(
    `INSERT INTO token_revocado (jti, usuario_id, expira_en)
     VALUES ($1, $2, to_timestamp($3)) ON CONFLICT (jti) DO NOTHING`,
    [req.token.jti, req.usuario.id, req.token.exp],
  );
  await registrar({ usuarioId: req.usuario.id, accion: 'LOGOUT', ip: ipDe(req) });
  return res.status(204).end();
});

router.get('/me', autenticar, (req, res) => {
  const { id, nombre_usuario: nombreUsuario, nombre, rol, paciente_id: pacienteId } = req.usuario;
  res.json({ id, nombre_usuario: nombreUsuario, nombre, rol, paciente_id: pacienteId });
});

module.exports = router;
