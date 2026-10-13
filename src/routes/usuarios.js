// RF-2.5 a RF-2.7: gestión de usuarios (solo administrador, RB-2)
const express = require('express');
const db = require('../db');
const { requerirRol } = require('../middleware/auth');
const { registrar, ipDe } = require('../services/auditoria');
const { ErrorHttp, correoValido, textoRequerido, idValido } = require('../utils/validaciones');

const router = express.Router();
router.use(requerirRol('admin'));

const ROLES = ['admin', 'medico', 'paciente'];
const COLUMNAS = 'id, nombre_usuario, nombre, correo, rol, paciente_id, activo, creado_en';

const revocarSesiones = (cliente, usuarioId) =>
  cliente.query(
    'UPDATE refresh_token SET revocado_en = now() WHERE usuario_id = $1 AND revocado_en IS NULL',
    [usuarioId],
  );

// RF-2.5: listar usuarios registrados
router.get('/', async (req, res) => {
  const params = [];
  const filtros = ['eliminado_en IS NULL'];
  const q = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 60) : '';
  if (q) {
    params.push(`%${q}%`);
    filtros.push(`(nombre_usuario ILIKE $${params.length} OR nombre ILIKE $${params.length} OR correo ILIKE $${params.length})`);
  }
  if (ROLES.includes(req.query.rol)) {
    params.push(req.query.rol);
    filtros.push(`rol = $${params.length}`);
  }
  const { rows } = await db.query(
    `SELECT ${COLUMNAS} FROM usuario WHERE ${filtros.join(' AND ')} ORDER BY id`,
    params,
  );
  res.json({ datos: rows });
});

router.get('/:id', async (req, res) => {
  const id = idValido(req.params.id);
  const { rows } = await db.query(
    `SELECT ${COLUMNAS} FROM usuario WHERE id = $1 AND eliminado_en IS NULL`,
    [id],
  );
  if (!rows[0]) throw new ErrorHttp(404, 'Usuario no encontrado');
  res.json(rows[0]);
});

// RF-2.6: editar usuario y asignar rol
router.put('/:id', async (req, res) => {
  const id = idValido(req.params.id);
  const body = req.body || {};

  const actual = await db.query(
    `SELECT ${COLUMNAS} FROM usuario WHERE id = $1 AND eliminado_en IS NULL`,
    [id],
  );
  if (!actual.rows[0]) throw new ErrorHttp(404, 'Usuario no encontrado');

  const datos = {};
  if (body.nombre !== undefined) datos.nombre = textoRequerido(body.nombre, 'nombre', 120);
  if (body.correo !== undefined) {
    if (!correoValido(body.correo)) throw new ErrorHttp(400, 'Correo inválido');
    datos.correo = body.correo.trim();
  }
  if (body.rol !== undefined) {
    if (!ROLES.includes(body.rol)) throw new ErrorHttp(400, 'Rol inválido (admin, medico o paciente)');
    datos.rol = body.rol;
  }
  if (body.activo !== undefined) {
    if (typeof body.activo !== 'boolean') throw new ErrorHttp(400, 'activo debe ser true o false');
    datos.activo = body.activo;
  }
  if (body.paciente_id !== undefined) {
    datos.paciente_id = body.paciente_id === null ? null : idValido(body.paciente_id);
  }

  const rolFinal = datos.rol ?? actual.rows[0].rol;
  if (rolFinal !== 'paciente') datos.paciente_id = null; // solo los pacientes tienen ficha
  if (datos.paciente_id) {
    const p = await db.query('SELECT 1 FROM paciente WHERE id = $1 AND eliminado_en IS NULL', [datos.paciente_id]);
    if (p.rowCount === 0) throw new ErrorHttp(400, 'La ficha de paciente indicada no existe');
  }

  // El administrador no puede quitarse su propio acceso
  if (id === req.usuario.id && (rolFinal !== 'admin' || datos.activo === false)) {
    throw new ErrorHttp(400, 'No puede quitarse su propio rol de administrador ni desactivarse');
  }

  const permitidas = ['nombre', 'correo', 'rol', 'activo', 'paciente_id'];
  const columnas = permitidas.filter((c) => datos[c] !== undefined);
  if (columnas.length === 0) throw new ErrorHttp(400, 'No hay campos para actualizar');

  const sets = columnas.map((c, i) => `${c} = $${i + 1}`);
  const params = columnas.map((c) => datos[c]);
  params.push(id);

  try {
    const usuario = await db.transaccion(async (cliente) => {
      const { rows } = await cliente.query(
        `UPDATE usuario SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING ${COLUMNAS}`,
        params,
      );
      if (datos.activo === false || (datos.rol && datos.rol !== actual.rows[0].rol)) {
        await revocarSesiones(cliente, id);
      }
      const cambioRol =
        datos.rol && datos.rol !== actual.rows[0].rol ? ` (rol ${actual.rows[0].rol} → ${datos.rol})` : '';
      await registrar(
        {
          usuarioId: req.usuario.id,
          accion: 'UPDATE',
          tabla: 'usuario',
          registroId: id,
          descripcion: `Campos actualizados: ${columnas.join(', ')}${cambioRol}`,
          ip: ipDe(req),
        },
        cliente,
      );
      return rows[0];
    });
    return res.json(usuario);
  } catch (err) {
    if (err.code === '23505') throw new ErrorHttp(409, 'El correo ya está registrado');
    throw err;
  }
});

// RF-2.7: eliminar usuario (eliminación lógica; se conserva para trazabilidad)
router.delete('/:id', async (req, res) => {
  const id = idValido(req.params.id);
  if (id === req.usuario.id) throw new ErrorHttp(400, 'No puede eliminar su propia cuenta');

  await db.transaccion(async (cliente) => {
    const { rowCount } = await cliente.query(
      'UPDATE usuario SET activo = false, eliminado_en = now() WHERE id = $1 AND eliminado_en IS NULL',
      [id],
    );
    if (rowCount === 0) throw new ErrorHttp(404, 'Usuario no encontrado');
    await revocarSesiones(cliente, id);
    await registrar(
      {
        usuarioId: req.usuario.id,
        accion: 'DELETE',
        tabla: 'usuario',
        registroId: id,
        descripcion: 'Eliminación lógica de usuario',
        ip: ipDe(req),
      },
      cliente,
    );
  });
  return res.status(204).end();
});

module.exports = router;