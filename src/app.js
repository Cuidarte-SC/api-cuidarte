// Aplicación Express de Cuidarte+

const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const multer = require('multer');
const config = require('./config');
const db = require('./db');
const { autenticar } = require('./middleware/auth');
const { ErrorHttp } = require('./utils/validaciones');

const app = express();

// No se confía en X-Forwarded-For: evita que un cliente falsifique su IP en auditoría y rate limit
app.set('trust proxy', false);
app.use(helmet()); // cabeceras de seguridad (HSTS, nosniff, CSP, etc.)
app.use(
  cors({
    origin: config.corsOrigenes,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Authorization', 'Content-Type'],
  }),
);
app.use(express.json({ limit: '100kb' }));

// Log de peticiones sin cuerpo ni cabeceras: nunca se registran contraseñas ni tokens (NFR-SEG-6)
app.use((req, res, next) => {
  const inicio = process.hrtime.bigint();
  res.on('finish', () => {
    const ms = Number(process.hrtime.bigint() - inicio) / 1e6;
    const usuario = req.usuario ? `usuario=${req.usuario.id}` : 'anonimo';
        console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl.split('?')[0]} ${res.statusCode} ${ms.toFixed(1)}ms ${usuario}`);
  });
  next();
});

// Salud del servicio (monitoreo de disponibilidad, NFR-DIS)
app.get('/api/salud', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ estado: 'ok', bd: 'ok', fecha: new Date().toISOString() });
  } catch {
    res.status(503).json({ estado: 'degradado', bd: 'sin conexión' });
  }
});

// Documentación OpenAPI interactiva (ERS 3.1.2). Se desactiva con SWAGGER_UI=false.
  if (process.env.SWAGGER_UI !== 'false') {
    const swaggerUi = require('swagger-ui-express');
    const YAML = require('yaml');
    const rutaSpec = path.join(__dirname, '..', 'docs', 'openapi.yaml');
    const especificacion = YAML.parse(fs.readFileSync(rutaSpec, 'utf8'));
    app.get('/api/openapi.yaml', (req, res) => res.type('text/yaml').sendFile(rutaSpec));
    app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(especificacion, { customSiteTitle: 'Cuidarte+ API' }));
  }

// Rutas públicas
app.use('/api/auth', require('./routes/auth'));

// Todo lo demás requiere sesión
app.use('/api', autenticar);
app.use('/api/pacientes', require('./routes/pacientes'));
app.use('/api/pacientes/:pacienteId/examenes', require('./routes/examenes'));
app.use('/api/auditoria', require('./routes/auditoria'));
app.use('/api/usuarios', require('./routes/usuarios'));
app.use('/api', require('./routes/documentos'));

app.use('/api', (req, res) => res.status(404).json({ error: 'Recurso no encontrado' }));

// Manejo central de errores: nunca expone detalles internos al cliente
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err instanceof ErrorHttp) {
    return res.status(err.status).json({ error: err.message });
  }
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    const mensaje = err.code === 'LIMIT_FILE_SIZE' ? 'El archivo supera 10 MB' : 'Carga de archivo inválida';
    return res.status(status).json({ error: mensaje });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'JSON mal formado' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Cuerpo de la petición demasiado grande' });
  }
  console.error('[error]', err.message);
  return res.status(500).json({ error: 'Error interno del servidor' });
});

module.exports = app;
