// RF-1: autenticación y sesión · RF-2.1: autoregistro
const express = require('express');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const config = require('../config');
const db = require('../db');
const { autenticar } = require('../middleware/auth');
const { registrar, ipDe } = require('../services/auditoria');
const { ErrorHttp, correoValido, passwordRobusta } = require('../utils/validaciones');

const router = express.Router();

const limitador = (limite, minutos, mensaje) =>
  rateLimit({
    windowMs: minutos * 60 * 1000,
    limit: limite,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: mensaje },
  });

// Fuerza bruta: 10 intentos de login cada 15 min por IP
const limiteLogin = limitador(10, 15, 'Demasiados intentos de inicio de sesión, intente en 15 minutos');
const limiteRegistro = limitador(5, 60, 'Demasiados registros desde esta conexión, intente más tarde');
const limiteRefresh = limitador(60, 15, 'Demasiadas renovaciones de sesión, intente más tarde');

// Hash ficticio para que un usuario inexistente tarde lo mismo que uno real
const HASH_FICTICIO = bcrypt.hashSync('usuario-inexistente-cuidarte', config.bcryptCosto);

const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex');

const datosPublicos = (u) => ({
  id: u.id,
  nombre_usuario: u.nombre_usuario,
  nombre: u.nombre,
  rol: u.rol,
  paciente_id: u.paciente_id,
});

// Emite el token de acceso (JWT corto) y el refresh token (opaco, se guarda solo su hash)
const emitirSesion = async (usuario, cliente = db) => {
  const token = jwt.sign({ rol: usuario.rol }, config.jwt.secreto, {
    algorithm: config.jwt.algoritmo,
    expiresIn: config.jwt.expiraEn,
    subject: String(usuario.id),
    jwtid: crypto.randomUUID(),
  });
  const { exp } = jwt.decode(token);

  const refresh = crypto.randomBytes(48).toString('base64url');
  await cliente.query(
    `INSERT INTO refresh_token (usuario_id, token_hash, expira_en)
     VALUES ($1, $2, now() + make_interval(hours => $3))`,
    [usuario.id, hashToken(refresh), config.refreshHoras],
  );

  return {
    token,
    tipo: 'Bearer',
    expira_en: new Date(exp * 1000).toISOString(),
    refresh_token: refresh,
    usuario: datosPublicos(usuario),
  };
};

router.post('/login', limiteLogin, async (req, res) => {
  const { nombre_usuario: nombreUsuario, password } = req.body || {};

  if (typeof nombreUsuario !== 'string' || typeof password !== 'string' || !nombreUsuario || !password) {
    return res.status(400).json({ error: 'Debe indicar nombre_usuario y password' });
  }

  const { rows } = await db.query(
    `SELECT id, nombre_usuario, nombre, rol, paciente_id, password_hash, activo
     FROM usuario WHERE nombre_usuario = $1 AND eliminado_en IS NULL`,
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

  const sesion = await emitirSesion(usuario);
  await registrar({ usuarioId: usuario.id, accion: 'LOGIN', ip: ipDe(req) });
  return res.status(200).json(sesion);
});

// RF-2.1: autoregistro público. El rol SIEMPRE es 'paciente'; cualquier rol enviado se ignora.
router.post('/registro', limiteRegistro, async (req, res) => {
  const { nombre_usuario: nombreUsuario, password, correo, nombre } = req.body || {};

  if (typeof nombreUsuario !== 'string' || !/^[A-Za-z0-9._-]{3,50}$/.test(nombreUsuario)) {
    throw new ErrorHttp(400, 'Nombre de usuario inválido: 3 a 50 caracteres (letras, números, punto, guion)');
  }
  if (!correoValido(correo)) throw new ErrorHttp(400, 'Correo inválido');
  if (!passwordRobusta(password)) {
    throw new ErrorHttp(
      400,
      'La contraseña debe tener entre 12 y 72 caracteres, con mayúscula, minúscula, número y símbolo',
    );
  }
  const nombreVisible =
    typeof nombre === 'string' && nombre.trim() ? nombre.trim().slice(0, 120) : nombreUsuario;

  try {
    const hash = await bcrypt.hash(password, config.bcryptCosto);
    const { rows } = await db.query(
      `INSERT INTO usuario (nombre_usuario, password_hash, rol, nombre, correo)
       VALUES ($1, $2, 'paciente', $3, $4)
       RETURNING id, nombre_usuario, nombre, rol, paciente_id`,
      [nombreUsuario, hash, nombreVisible, correo.trim()],
    );
    await registrar({
      usuarioId: rows[0].id,
      accion: 'CREATE',
      tabla: 'usuario',
      registroId: rows[0].id,
      descripcion: 'Autoregistro con rol paciente',
      ip: ipDe(req),
    });
    return res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') throw new ErrorHttp(409, 'El nombre de usuario o el correo ya están registrados');
    throw err;
  }
});

// Renovación de sesión con rotación: el refresh token usado queda revocado y se emite uno nuevo
router.post('/refresh', limiteRefresh, async (req, res) => {
  const refresh = req.body?.refresh_token;
  if (typeof refresh !== 'string' || refresh.length < 20) {
    return res.status(401).json({ error: 'Sesión expirada, inicie sesión nuevamente' });
  }

  const sesion = await db.transaccion(async (cliente) => {
    const { rows } = await cliente.query(
      `UPDATE refresh_token SET revocado_en = now()
       WHERE token_hash = $1 AND revocado_en IS NULL AND expira_en > now()
       RETURNING usuario_id`,
      [hashToken(refresh)],
    );
    if (!rows[0]) return null;

    const u = await cliente.query(
      `SELECT id, nombre_usuario, nombre, rol, paciente_id FROM usuario
       WHERE id = $1 AND activo AND eliminado_en IS NULL`,
      [rows[0].usuario_id],
    );
    if (!u.rows[0]) return null;
    return emitirSesion(u.rows[0], cliente);
  });

  if (!sesion) return res.status(401).json({ error: 'Sesión expirada, inicie sesión nuevamente' });
  return res.json(sesion);
});

// Logout: revoca el token de acceso actual y todos los refresh tokens del usuario
router.post('/logout', autenticar, async (req, res) => {
  await db.query(
    `INSERT INTO token_revocado (jti, usuario_id, expira_en)
     VALUES ($1, $2, to_timestamp($3)) ON CONFLICT (jti) DO NOTHING`,
    [req.token.jti, req.usuario.id, req.token.exp],
  );
  await db.query(
    'UPDATE refresh_token SET revocado_en = now() WHERE usuario_id = $1 AND revocado_en IS NULL',
    [req.usuario.id],
  );
  await registrar({ usuarioId: req.usuario.id, accion: 'LOGOUT', ip: ipDe(req) });
  return res.status(204).end();
});

router.get('/me', autenticar, (req, res) => {
  res.json(datosPublicos(req.usuario));
});

module.exports = router;