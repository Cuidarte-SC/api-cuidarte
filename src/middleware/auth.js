// Autenticación con JWT en el header Authorization: Bearer <token> (RF-1).
// Al no usar cookies para la sesión, la API no es vulnerable a CSRF clásico.
const jwt = require('jsonwebtoken');
const config = require('../config');
const db = require('../db');
const { registrar, ipDe } = require('../services/auditoria');

const autenticar = async (req, res, next) => {
  const header = req.get('authorization') || '';
  const [tipo, token] = header.split(' ');

  if (tipo !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Autenticación requerida' });
  }

  let payload;
  try {
    payload = jwt.verify(token, config.jwt.secreto, { algorithms: [config.jwt.algoritmo] });
  } catch {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }

  // Token revocado por logout
  const revocado = await db.query('SELECT 1 FROM token_revocado WHERE jti = $1', [payload.jti]);
  if (revocado.rowCount > 0) {
    return res.status(401).json({ error: 'Sesión cerrada, inicie sesión nuevamente' });
  }

  // El usuario debe seguir activo y el rol se toma de la BD, no del token
  const { rows } = await db.query(
    'SELECT id, nombre_usuario, nombre, rol, paciente_id, activo FROM usuario WHERE id = $1',
    [payload.sub],
  );
  const usuario = rows[0];
  if (!usuario || !usuario.activo) {
    return res.status(401).json({ error: 'Usuario no autorizado' });
  }

  req.usuario = usuario;
  req.token = { jti: payload.jti, exp: payload.exp };
  return next();
};

// RBAC aplicado en el backend (NFR-SEG-4). Los intentos rechazados quedan auditados.
const requerirRol = (...roles) => async (req, res, next) => {
  if (roles.includes(req.usuario.rol)) return next();

  await registrar({
    usuarioId: req.usuario.id,
    accion: 'ACCESO_DENEGADO',
    descripcion: `Rol ${req.usuario.rol} intentó ${req.method} ${req.originalUrl}`,
    ip: ipDe(req),
  });
  return res.status(403).json({ error: `Acceso denegado: rol ${req.usuario.rol} no autorizado` });
};

// Un paciente solo puede ver su propia ficha (RB-1); admin y médico ven todas (RB-2, RB-3).
const verificarAccesoPaciente = async (req, pacienteId) => {
  if (req.usuario.rol !== 'paciente' || req.usuario.paciente_id === pacienteId) return true;

  await registrar({
    usuarioId: req.usuario.id,
    accion: 'ACCESO_DENEGADO',
    pacienteId,
    descripcion: `Paciente intentó acceder a la ficha ${pacienteId}`,
    ip: ipDe(req),
  });
  return false;
};

module.exports = { autenticar, requerirRol, verificarAccesoPaciente };
