// Configuración centralizada: todo viene de variables de entorno.
const requerida = (nombre) => {
  const valor = process.env[nombre];
  if (!valor) {
    throw new Error(`Falta la variable de entorno ${nombre}`);
  }
  return valor;
};

const jwtSecret = requerida('JWT_SECRET');
if (jwtSecret.length < 32) {
  throw new Error('JWT_SECRET debe tener al menos 32 caracteres (NFR-SEG)');
}

module.exports = {
  puerto: Number(process.env.PORT || 4000),
  entorno: process.env.NODE_ENV || 'development',
  databaseUrl: requerida('DATABASE_URL'),
  jwt: {
    secreto: jwtSecret,
    expiraEn: process.env.JWT_EXPIRES_IN || '15m', // NFR-SEG-9: corta vigencia
    algoritmo: 'HS256',
  },
  documentosDir: process.env.DOCUMENTOS_DIR || '/data/documentos',
  corsOrigenes: (process.env.CORS_ORIGIN || 'http://localhost:8080,https://localhost:8443')
    .split(',')
    .map((o) => o.trim()),
  bcryptCosto: 12, // NFR-SEG-2
};
