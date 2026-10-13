// RF-2: registro y gestión de pacientes
const express = require('express');
const bcrypt = require('bcryptjs');
const config = require('../config');
const db = require('../db');
const { requerirRol, verificarAccesoPaciente } = require('../middleware/auth');
const { registrar, ipDe } = require('../services/auditoria');
const {
  ErrorHttp,
  rutValido,
  correoValido,
  fechaValida,
  passwordRobusta,
  textoRequerido,
  idValido,
} = require('../utils/validaciones');

const router = express.Router();

const COLUMNAS = 'id, rut, nombre, correo, fecha_nacimiento, consentimiento_datos, creado_en';

// Listado paginado con búsqueda por nombre o RUT (admin y médico)
router.get('/', requerirRol('admin', 'medico'), async (req, res) => {
  const limite = Math.min(Math.max(Number(req.query.limite) || 20, 1), 100);
  const pagina = Math.max(Number(req.query.pagina) || 1, 1);
  const busqueda = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 60) : '';

  const params = [];
  let filtro = 'WHERE eliminado_en IS NULL';
  if (busqueda) {
    params.push(`%${busqueda}%`);
    filtro += ` AND (nombre ILIKE $${params.length} OR rut ILIKE $${params.length})`;
  }

  const total = await db.query(`SELECT count(*)::int AS total FROM paciente ${filtro}`, params);
  params.push(limite, (pagina - 1) * limite);
  const { rows } = await db.query(
    `SELECT ${COLUMNAS} FROM paciente ${filtro} ORDER BY id LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  res.json({ datos: rows, pagina, limite, total: total.rows[0].total });
});

// Ficha de un paciente (el paciente solo la suya)
router.get('/:id', async (req, res) => {
  const id = idValido(req.params.id);
  if (!(await verificarAccesoPaciente(req, id))) {
    return res.status(403).json({ error: 'Acceso denegado: solo puede ver su propia ficha' });
  }

  const { rows } = await db.query(
    `SELECT ${COLUMNAS} FROM paciente WHERE id = $1 AND eliminado_en IS NULL`,
    [id],
  );
  if (!rows[0]) throw new ErrorHttp(404, 'Paciente no encontrado');

  await registrar({
    usuarioId: req.usuario.id,
    accion: 'READ',
    tabla: 'paciente',
    registroId: id,
    pacienteId: id,
    ip: ipDe(req),
  });
  return res.json(rows[0]);
});

// Registro de paciente por médico o administrador (RF-2.2)
// Opcional: "credenciales" crea la cuenta de acceso; el rol SIEMPRE es 'paciente'.
router.post('/', requerirRol('admin', 'medico'), async (req, res) => {
  const body = req.body || {};
  const nombre = textoRequerido(body.nombre, 'nombre', 120);

  if (!rutValido(body.rut)) {
    throw new ErrorHttp(400, 'RUT inválido: use el formato XX.XXX.XXX-D con dígito verificador correcto');
  }
  if (!correoValido(body.correo)) throw new ErrorHttp(400, 'Correo inválido');
  if (!fechaValida(body.fecha_nacimiento)) {
    throw new ErrorHttp(400, 'fecha_nacimiento inválida (formato AAAA-MM-DD)');
  }

  const credenciales = body.credenciales;
  if (credenciales) {
    textoRequerido(credenciales.nombre_usuario, 'credenciales.nombre_usuario', 50);
    if (!passwordRobusta(credenciales.password)) {
      throw new ErrorHttp(
        400,
        'La contraseña debe tener entre 12 y 72 caracteres, con mayúscula, minúscula, número y símbolo',
      );
    }
  }

  try {
    const resultado = await db.transaccion(async (cliente) => {
      const { rows } = await cliente.query(
        `INSERT INTO paciente (rut, nombre, correo, fecha_nacimiento, consentimiento_datos, creado_por)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING ${COLUMNAS}`,
        [body.rut, nombre, body.correo, body.fecha_nacimiento, body.consentimiento_datos === true, req.usuario.id],
      );
      const paciente = rows[0];

      let cuenta = null;
      if (credenciales) {
        const hash = await bcrypt.hash(credenciales.password, config.bcryptCosto);
        const u = await cliente.query(
          `INSERT INTO usuario (nombre_usuario, password_hash, rol, nombre, correo, paciente_id)
           VALUES ($1, $2, 'paciente', $3, $4, $5) RETURNING id, nombre_usuario, rol`,
          [credenciales.nombre_usuario.trim(), hash, nombre, body.correo, paciente.id],
        );
        cuenta = u.rows[0];
      }

      await registrar(
        {
          usuarioId: req.usuario.id,
          accion: 'CREATE',
          tabla: 'paciente',
          registroId: paciente.id,
          pacienteId: paciente.id,
          descripcion: cuenta ? 'Paciente creado con cuenta de acceso' : 'Paciente creado',
          ip: ipDe(req),
        },
        cliente,
      );
      return { ...paciente, rol: 'paciente', cuenta };
    });
    return res.status(201).json(resultado);
  } catch (err) {
    if (err.code === '23505') {
      throw new ErrorHttp(409, 'Ya existe un registro con ese RUT, nombre de usuario o correo');
    }
    throw err;
  }
});


// RF-2.3: editar el registro de un paciente (médico o admin)
router.put('/:id', requerirRol('admin', 'medico'), async (req, res) => {
  const id = idValido(req.params.id);
  const body = req.body || {};
  const datos = {};

  if (body.nombre !== undefined) datos.nombre = textoRequerido(body.nombre, 'nombre', 120);
  if (body.rut !== undefined) {
    if (!rutValido(body.rut)) {
      throw new ErrorHttp(400, 'RUT inválido: use el formato XX.XXX.XXX-D con dígito verificador correcto');
    }
    datos.rut = body.rut;
  }
  if (body.correo !== undefined) {
    if (!correoValido(body.correo)) throw new ErrorHttp(400, 'Correo inválido');
    datos.correo = body.correo.trim();
  }
  if (body.fecha_nacimiento !== undefined) {
    if (!fechaValida(body.fecha_nacimiento)) {
      throw new ErrorHttp(400, 'fecha_nacimiento inválida (formato AAAA-MM-DD)');
    }
    datos.fecha_nacimiento = body.fecha_nacimiento;
  }
  if (body.consentimiento_datos !== undefined) {
    if (typeof body.consentimiento_datos !== 'boolean') {
      throw new ErrorHttp(400, 'consentimiento_datos debe ser true o false');
    }
    datos.consentimiento_datos = body.consentimiento_datos;
  }

  // Lista blanca de columnas: los nombres nunca vienen del usuario
  const permitidas = ['nombre', 'rut', 'correo', 'fecha_nacimiento', 'consentimiento_datos'];
  const columnas = permitidas.filter((c) => datos[c] !== undefined);
  if (columnas.length === 0) throw new ErrorHttp(400, 'No hay campos para actualizar');

  const sets = columnas.map((c, i) => `${c} = $${i + 1}`);
  const params = columnas.map((c) => datos[c]);
  params.push(id);

  try {
    const paciente = await db.transaccion(async (cliente) => {
      const { rows } = await cliente.query(
        `UPDATE paciente SET ${sets.join(', ')}
         WHERE id = $${params.length} AND eliminado_en IS NULL RETURNING ${COLUMNAS}`,
        params,
      );
      if (!rows[0]) throw new ErrorHttp(404, 'Paciente no encontrado');
      await registrar(
        {
          usuarioId: req.usuario.id,
          accion: 'UPDATE',
          tabla: 'paciente',
          registroId: id,
          pacienteId: id,
          descripcion: `Campos actualizados: ${columnas.join(', ')}`,
          ip: ipDe(req),
        },
        cliente,
      );
      return rows[0];
    });
    return res.json(paciente);
  } catch (err) {
    if (err.code === '23505') throw new ErrorHttp(409, 'Ya existe un paciente con ese RUT');
    throw err;
  }
});


// Eliminación lógica (solo admin); se conserva para trazabilidad
router.delete('/:id', requerirRol('admin'), async (req, res) => {
  const id = idValido(req.params.id);
  const { rowCount } = await db.query(
    'UPDATE paciente SET eliminado_en = now() WHERE id = $1 AND eliminado_en IS NULL',
    [id],
  );
  if (rowCount === 0) throw new ErrorHttp(404, 'Paciente no encontrado');

  await registrar({
    usuarioId: req.usuario.id,
    accion: 'DELETE',
    tabla: 'paciente',
    registroId: id,
    pacienteId: id,
    descripcion: 'Eliminación lógica',
    ip: ipDe(req),
  });
  return res.status(204).end();
});

module.exports = router;
