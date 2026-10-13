const app = require('./app');
const config = require('./config');
const { pool } = require('./db');
const { migrarCifrado } = require('./services/migracionCifrado');

let servidor;

// Antes de aceptar peticiones, cifra lo que aún esté en texto plano (NFR-SEG-3)
migrarCifrado()
  .then(() => {
    servidor = app.listen(config.puerto, () => {
      console.log(`API Cuidarte+ escuchando en el puerto ${config.puerto} (${config.entorno})`);
    });
  })
  .catch((err) => {
    console.error('[cifrado] no se pudo completar la migración:', err.message);
    process.exit(1);
  });

const cerrar = () => {
  console.log('Cerrando API Cuidarte+...');
  if (!servidor) process.exit(0);
  servidor.close(() => pool.end().then(() => process.exit(0)));
};
process.on('SIGTERM', cerrar);
process.on('SIGINT', cerrar);