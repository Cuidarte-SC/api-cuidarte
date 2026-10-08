// Registro de acciones críticas (RF-5, NFR-SEG-6).
// La tabla es de solo inserción: la BD bloquea UPDATE, DELETE y TRUNCATE.
const db = require('../db');

const registrar = async (
  { usuarioId = null, accion, tabla = null, registroId = null, pacienteId = null, descripcion = null, ip = null },
  cliente = db,
) => {
  await cliente.query(
    `INSERT INTO auditoria (usuario_id, accion, tabla_afectada, registro_id, paciente_id, descripcion, ip_origen)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [usuarioId, accion, tabla, registroId, pacienteId, descripcion, ip],
  );
};

// IP de origen normalizada (quita el prefijo IPv6 de direcciones IPv4)
const ipDe = (req) => {
  const ip = req.ip || null;
  return ip && ip.startsWith('::ffff:') ? ip.slice(7) : ip;
};

module.exports = { registrar, ipDe };
