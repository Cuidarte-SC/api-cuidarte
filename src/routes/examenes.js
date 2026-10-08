// RF-3: gestión de exámenes médicos. Montado en /api/pacientes/:pacienteId/examenes
const express = require('express');
const db = require('../db');
const { requerirRol, verificarAccesoPaciente } = require('../middleware/auth');
const { registrar, ipDe } = require('../services/auditoria');
const { ErrorHttp, fechaValida, textoRequerido, idValido } = require('../utils/validaciones');

const router = express.Router({ mergeParams: true });

const COLUMNAS =
  'id, paciente_id, medico_id, tipo_examen, fecha_examen, resultado, estado, creado_en, actualizado_en';
const ESTADOS = ['pendiente', 'disponible'];

const pacienteExiste = async (id) => {
  const { rowCount } = await db.query(
    'SELECT 1 FROM paciente WHERE id = $1 AND eliminado_en IS NULL',
    [id],
  );
  if (rowCount === 0) throw new ErrorHttp(404, 'Paciente no encontrado');
};

const validarExamen = (body, parcial = false) => {
  const datos = {};
  if (!parcial || body.tipo_examen !== undefined) {
    datos.tipo_examen = textoRequerido(body.tipo_examen, 'tipo_examen', 80);
  }
  if (!parcial || body.fecha_examen !== undefined) {
    if (!fechaValida(body.fecha_examen)) throw new ErrorHttp(400, 'fecha_examen inválida (AAAA-MM-DD)');
    datos.fecha_examen = body.fecha_examen;
  }
  if (body.resultado !== undefined) {
    if (typeof body.resultado !== 'string' || body.resultado.length > 5000) {
      throw new ErrorHttp(400, 'resultado debe ser texto de hasta 5000 caracteres');
    }
    datos.resultado = body.resultado;
  }
  if (body.estado !== undefined) {
    if (!ESTADOS.includes(body.estado)) throw new ErrorHttp(400, 'estado debe ser pendiente o disponible');
    datos.estado = body.estado;
  }
  return datos;
};

// Listar exámenes del paciente
router.get('/', async (req, res) => {
  const pacienteId = idValido(req.params.pacienteId);
  if (!(await verificarAccesoPaciente(req, pacienteId))) {
    return res.status(403).json({ error: 'Acceso denegado: solo puede ver sus propios exámenes' });
  }
  await pacienteExiste(pacienteId);

  const { rows } = await db.query(
    `SELECT ${COLUMNAS} FROM examen WHERE paciente_id = $1 ORDER BY fecha_examen DESC, id DESC`,
    [pacienteId],
  );
  await registrar({
    usuarioId: req.usuario.id,
    accion: 'READ',
    tabla: 'examen',
    pacienteId,
    descripcion: `Listado de ${rows.length} exámenes`,
    ip: ipDe(req),
  });
  return res.json({ datos: rows });
});

// Ver un examen
router.get('/:examenId', async (req, res) => {
  const pacienteId = idValido(req.params.pacienteId);
  const examenId = idValido(req.params.examenId);
  if (!(await verificarAccesoPaciente(req, pacienteId))) {
    return res.status(403).json({ error: 'Acceso denegado: solo puede ver sus propios exámenes' });
  }

  const { rows } = await db.query(
    `SELECT ${COLUMNAS} FROM examen WHERE id = $1 AND paciente_id = $2`,
    [examenId, pacienteId],
  );
  if (!rows[0]) throw new ErrorHttp(404, 'Examen no encontrado');

  await registrar({
    usuarioId: req.usuario.id,
    accion: 'READ',
    tabla: 'examen',
    registroId: examenId,
    pacienteId,
    ip: ipDe(req),
  });
  return res.json(rows[0]);
});

// Crear examen (médico o admin) + auditoría en la misma transacción (RF-3.1, RF-5.1)
router.post('/', requerirRol('admin', 'medico'), async (req, res) => {
  const pacienteId = idValido(req.params.pacienteId);
  const datos = validarExamen(req.body || {});
  await pacienteExiste(pacienteId);

  const examen = await db.transaccion(async (cliente) => {
    const { rows } = await cliente.query(
      `INSERT INTO examen (paciente_id, medico_id, tipo_examen, fecha_examen, resultado, estado)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING ${COLUMNAS}`,
      [
        pacienteId,
        req.usuario.id,
        datos.tipo_examen,
        datos.fecha_examen,
        datos.resultado ?? null,
        datos.estado ?? (datos.resultado ? 'disponible' : 'pendiente'),
      ],
    );
    await registrar(
      {
        usuarioId: req.usuario.id,
        accion: 'CREATE',
        tabla: 'examen',
        registroId: rows[0].id,
        pacienteId,
        descripcion: `Examen "${datos.tipo_examen}" creado`,
        ip: ipDe(req),
      },
      cliente,
    );
    return rows[0];
  });
  return res.status(201).json(examen);
});

// Actualizar examen (médico o admin)
router.put('/:examenId', requerirRol('admin', 'medico'), async (req, res) => {
  const pacienteId = idValido(req.params.pacienteId);
  const examenId = idValido(req.params.examenId);
  const datos = validarExamen(req.body || {}, true);

  // Lista blanca de columnas: los nombres nunca vienen del usuario
  const permitidas = ['tipo_examen', 'fecha_examen', 'resultado', 'estado'];
  const columnas = permitidas.filter((c) => datos[c] !== undefined);
  if (columnas.length === 0) throw new ErrorHttp(400, 'No hay campos para actualizar');

  const sets = columnas.map((c, i) => `${c} = $${i + 1}`);
  const params = columnas.map((c) => datos[c]);
  params.push(examenId, pacienteId);

  const examen = await db.transaccion(async (cliente) => {
    const { rows } = await cliente.query(
      `UPDATE examen SET ${sets.join(', ')}, actualizado_en = now()
       WHERE id = $${params.length - 1} AND paciente_id = $${params.length} RETURNING ${COLUMNAS}`,
      params,
    );
    if (!rows[0]) throw new ErrorHttp(404, 'Examen no encontrado');
    await registrar(
      {
        usuarioId: req.usuario.id,
        accion: 'UPDATE',
        tabla: 'examen',
        registroId: examenId,
        pacienteId,
        descripcion: `Campos actualizados: ${columnas.join(', ')}`,
        ip: ipDe(req),
      },
      cliente,
    );
    return rows[0];
  });
  return res.json(examen);
});

module.exports = router;
