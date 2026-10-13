// RF-4: documentos médicos asociados a un examen
// RF-4.3: un documento activo por examen; subir uno nuevo reemplaza al anterior (nueva versión, RF-3.2)
// RF-3.3: eliminación lógica de documentos
const express = require('express');
const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');
const multer = require('multer');
const config = require('../config');
const db = require('../db');
const { requerirRol, verificarAccesoPaciente } = require('../middleware/auth');
const { registrar, ipDe } = require('../services/auditoria');
const { ErrorHttp, idValido } = require('../utils/validaciones');
const { cifrarArchivo, descifrarArchivo } = require('../services/cifrado');

const router = express.Router();

const TAMANO_MAXIMO = 10 * 1024 * 1024; // 10 MB

// Tipo declarado -> firma real del archivo (magic bytes). Evita subir un ejecutable renombrado.
const FIRMAS = {
  'application/pdf': [[0x25, 0x50, 0x44, 0x46]], // %PDF
  'image/png': [[0x89, 0x50, 0x4e, 0x47]],
  'image/jpeg': [[0xff, 0xd8, 0xff]],
  'application/msword': [[0xd0, 0xcf, 0x11, 0xe0]], // OLE (doc)
  'application/vnd.ms-powerpoint': [[0xd0, 0xcf, 0x11, 0xe0]], // OLE (ppt)
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [[0x50, 0x4b, 0x03, 0x04]], // ZIP
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': [[0x50, 0x4b, 0x03, 0x04]],
};

const firmaCoincide = (buffer, mime) =>
  (FIRMAS[mime] || []).some((firma) => firma.every((byte, i) => buffer[i] === byte));

const subida = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: TAMANO_MAXIMO, files: 1 },
});

fs.mkdirSync(config.documentosDir, { recursive: true });

const COLUMNAS = 'id, examen_id, paciente_id, nombre_archivo, mime_type, tamano_bytes, version, subido_en';

// Obtiene el examen (no eliminado) y valida que el usuario pueda acceder a su paciente
const examenAccesible = async (req, examenId) => {
  const { rows } = await db.query(
    'SELECT id, paciente_id FROM examen WHERE id = $1 AND eliminado_en IS NULL',
    [examenId],
  );
  if (!rows[0]) throw new ErrorHttp(404, 'Examen no encontrado');
  if (!(await verificarAccesoPaciente(req, rows[0].paciente_id))) {
    throw new ErrorHttp(403, 'Acceso denegado: el documento pertenece a otro paciente');
  }
  return rows[0];
};

// Subir documento (médico o admin), campo multipart "archivo"
router.post(
  '/examenes/:examenId/documentos',
  requerirRol('admin', 'medico'),
  subida.single('archivo'),
  async (req, res) => {
    const examenId = idValido(req.params.examenId);
    const examen = await examenAccesible(req, examenId);

    const archivo = req.file;
    if (!archivo) throw new ErrorHttp(400, 'Debe adjuntar un archivo en el campo "archivo"');
    if (!Object.hasOwn(FIRMAS, archivo.mimetype) || !firmaCoincide(archivo.buffer, archivo.mimetype)) {
      throw new ErrorHttp(415, 'Tipo de archivo no permitido (PDF, DOC/DOCX, PPT/PPTX, JPG o PNG)');
    }

    // Nombre en disco generado por el servidor: nunca se usa el nombre enviado por el cliente
    const nombreInterno = crypto.randomUUID();
    const ruta = path.join(config.documentosDir, nombreInterno);
    // NFR-SEG-3: el archivo se guarda cifrado en disco
    await fs.promises.writeFile(ruta, cifrarArchivo(archivo.buffer), { flag: 'wx' });

    const nombreOriginal = path.basename(archivo.originalname).slice(0, 255);

    const documento = await db.transaccion(async (cliente) => {
      // El documento activo anterior queda reemplazado (se conserva como versión previa)
      const anterior = await cliente.query(
        'UPDATE documento SET eliminado_en = now() WHERE examen_id = $1 AND eliminado_en IS NULL RETURNING id',
        [examenId],
      );
      const version = await cliente.query(
        'SELECT COALESCE(max(version), 0) + 1 AS v FROM documento WHERE examen_id = $1',
        [examenId],
      );
      const { rows } = await cliente.query(
        `INSERT INTO documento (examen_id, paciente_id, nombre_archivo, mime_type, tamano_bytes,
                                ruta_almacenamiento, version, subido_por)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING ${COLUMNAS}`,
        [
          examenId,
          examen.paciente_id,
          nombreOriginal,
          archivo.mimetype,
          archivo.size,
          nombreInterno,
          version.rows[0].v,
          req.usuario.id,
        ],
      );
      const reemplazo = anterior.rowCount > 0 ? ` reemplaza al documento ${anterior.rows[0].id}` : '';
      await registrar(
        {
          usuarioId: req.usuario.id,
          accion: anterior.rowCount > 0 ? 'UPDATE' : 'CREATE',
          tabla: 'documento',
          registroId: rows[0].id,
          pacienteId: examen.paciente_id,
          descripcion: `Documento v${rows[0].version} subido (${archivo.mimetype}, ${archivo.size} bytes)${reemplazo}`,
          ip: ipDe(req),
        },
        cliente,
      );
      return rows[0];
    });

    return res.status(201).json(documento);
  },
);

// Listar el documento activo de un examen
router.get('/examenes/:examenId/documentos', async (req, res) => {
  const examenId = idValido(req.params.examenId);
  await examenAccesible(req, examenId);

  const { rows } = await db.query(
    `SELECT ${COLUMNAS} FROM documento WHERE examen_id = $1 AND eliminado_en IS NULL`,
    [examenId],
  );
  return res.json({ datos: rows });
});

// Busca un documento activo y valida el acceso del usuario
const documentoAccesible = async (req, id) => {
  const { rows } = await db.query(
    `SELECT id, examen_id, paciente_id, nombre_archivo, mime_type, ruta_almacenamiento
     FROM documento WHERE id = $1 AND eliminado_en IS NULL`,
    [id],
  );
  const documento = rows[0];
  if (!documento) throw new ErrorHttp(404, 'Documento no encontrado');
  if (!(await verificarAccesoPaciente(req, documento.paciente_id))) {
    throw new ErrorHttp(403, 'Acceso denegado: el documento pertenece a otro paciente');
  }
  return documento;
};

// Descargar documento (RF-4.2)
router.get('/documentos/:id/descarga', async (req, res) => {
  const id = idValido(req.params.id);
  const documento = await documentoAccesible(req, id);

  const ruta = path.join(config.documentosDir, path.basename(documento.ruta_almacenamiento));
  if (!fs.existsSync(ruta)) throw new ErrorHttp(404, 'Archivo no disponible en el almacenamiento');

  await registrar({
    usuarioId: req.usuario.id,
    accion: 'DESCARGA',
    tabla: 'documento',
    registroId: id,
    pacienteId: documento.paciente_id,
    ip: ipDe(req),
  });

  // NFR-SEG-3: se descifra en memoria solo para quien tiene acceso
  const contenido = descifrarArchivo(await fs.promises.readFile(ruta));
  res.attachment(documento.nombre_archivo);
  res.type(documento.mime_type);
  return res.send(contenido);
});

// RF-3.3: eliminar documento (lógico; el archivo se conserva para trazabilidad)
router.delete('/documentos/:id', requerirRol('admin', 'medico'), async (req, res) => {
  const id = idValido(req.params.id);
  const documento = await documentoAccesible(req, id);

  await db.transaccion(async (cliente) => {
    await cliente.query('UPDATE documento SET eliminado_en = now() WHERE id = $1', [id]);
    await registrar(
      {
        usuarioId: req.usuario.id,
        accion: 'DELETE',
        tabla: 'documento',
        registroId: id,
        pacienteId: documento.paciente_id,
        descripcion: 'Eliminación lógica de documento',
        ip: ipDe(req),
      },
      cliente,
    );
  });
  return res.status(204).end();
});

module.exports = router;