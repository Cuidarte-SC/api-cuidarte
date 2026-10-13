// NFR-SEG-3: cifra los datos que aún estén en texto plano (por ejemplo, los del seed inicial).
// Se ejecuta al iniciar la API y es idempotente: lo ya cifrado no se vuelve a tocar.
const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');
const db = require('../db');
const { cifrarTexto, cifrarArchivo, archivoCifrado } = require('./cifrado');

const migrarResultados = async () => {
  const { rows } = await db.query(
    "SELECT id, resultado FROM examen WHERE resultado IS NOT NULL AND resultado NOT LIKE 'enc:v1:%'",
  );
  if (rows.length === 0) return 0;

  await db.transaccion(async (cliente) => {
    for (const fila of rows) {
      await cliente.query('UPDATE examen SET resultado = $1 WHERE id = $2', [cifrarTexto(fila.resultado), fila.id]);
    }
  });
  return rows.length;
};

const migrarArchivos = async () => {
  const { rows } = await db.query('SELECT ruta_almacenamiento FROM documento');
  let cifrados = 0;
  for (const { ruta_almacenamiento: nombre } of rows) {
    const ruta = path.join(config.documentosDir, path.basename(nombre));
    if (!fs.existsSync(ruta)) continue;
    const contenido = await fs.promises.readFile(ruta);
    if (archivoCifrado(contenido)) continue;
    await fs.promises.writeFile(ruta, cifrarArchivo(contenido));
    cifrados += 1;
  }
  return cifrados;
};

const migrarCifrado = async () => {
  const resultados = await migrarResultados();
  const archivos = await migrarArchivos();
  console.log(`[cifrado] migración en reposo: ${resultados} resultado(s) y ${archivos} archivo(s) cifrados`);
};

module.exports = { migrarCifrado };