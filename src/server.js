const app = require('./app');
const config = require('./config');
const { pool } = require('./db');

const servidor = app.listen(config.puerto, () => {
  console.log(`API Cuidarte+ escuchando en el puerto ${config.puerto} (${config.entorno})`);
});

const cerrar = () => {
  console.log('Cerrando API Cuidarte+...');
  servidor.close(() => pool.end().then(() => process.exit(0)));
};
process.on('SIGTERM', cerrar);
process.on('SIGINT', cerrar);
