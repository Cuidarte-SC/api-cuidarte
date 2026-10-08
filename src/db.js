// Pool de conexiones a PostgreSQL. Todas las consultas usan parámetros ($1, $2...)
// para prevenir SQL Injection (NFR-SEG-5).
const { Pool } = require('pg');
const config = require('./config');

const pool = new Pool({
  connectionString: config.databaseUrl,
  max: 20,
  idleTimeoutMillis: 30000,
});

pool.on('error', (err) => {
  console.error('[db] error inesperado en el pool:', err.message);
});

const query = (texto, params) => pool.query(texto, params);

// Ejecuta una función dentro de una transacción (BEGIN/COMMIT/ROLLBACK).
const transaccion = async (fn) => {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const resultado = await fn(cliente);
    await cliente.query('COMMIT');
    return resultado;
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
};

module.exports = { pool, query, transaccion };
