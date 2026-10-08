// RF-5: consulta de auditoría (solo administrador)
const express = require('express');
const db = require('../db');
const { requerirRol } = require('../middleware/auth');
const { idValido } = require('../utils/validaciones');

const router = express.Router();

router.get('/', requerirRol('admin'), async (req, res) => {
  const limite = Math.min(Math.max(Number(req.query.limite) || 50, 1), 500);
  const params = [];
  const filtros = [];

  if (req.query.paciente_id !== undefined) {
    params.push(idValido(req.query.paciente_id));
    filtros.push(`a.paciente_id = $${params.length}`);
  }
  if (req.query.usuario_id !== undefined) {
    params.push(idValido(req.query.usuario_id));
    filtros.push(`a.usuario_id = $${params.length}`);
  }
  if (typeof req.query.accion === 'string') {
    params.push(req.query.accion.toUpperCase());
    filtros.push(`a.accion = $${params.length}`);
  }
  params.push(limite);

  const where = filtros.length ? `WHERE ${filtros.join(' AND ')}` : '';
  const { rows } = await db.query(
    `SELECT a.id, a.usuario_id, u.nombre_usuario, a.accion, a.tabla_afectada, a.registro_id,
            a.paciente_id, a.descripcion, a.ip_origen, a.creado_en
     FROM auditoria a LEFT JOIN usuario u ON u.id = a.usuario_id
     ${where}
     ORDER BY a.creado_en DESC, a.id DESC
     LIMIT $${params.length}`,
    params,
  );
  res.json({ datos: rows });
});

module.exports = router;
