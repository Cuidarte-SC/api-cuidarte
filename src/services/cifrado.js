// NFR-SEG-3: cifrado de datos sensibles en reposo con AES-256-GCM.
// La clave (32 bytes) vive en la variable DATA_ENCRYPTION_KEY, nunca en la BD ni en Git.
// GCM además autentica: si alguien altera el dato cifrado, el descifrado falla.
const crypto = require('node:crypto');
const config = require('../config');

const ALGORITMO = 'aes-256-gcm';
const PREFIJO_TEXTO = 'enc:v1:'; // marca los textos cifrados en la BD
const MARCA_ARCHIVO = Buffer.from('CDE1'); // marca los archivos cifrados en disco
const IV = 12;
const TAG = 16;

const clave = Buffer.from(config.claveDatos, 'hex');

const cifrar = (datos) => {
  const iv = crypto.randomBytes(IV); // IV aleatorio por cada dato
  const cifrador = crypto.createCipheriv(ALGORITMO, clave, iv);
  const contenido = Buffer.concat([cifrador.update(datos), cifrador.final()]);
  return Buffer.concat([iv, cifrador.getAuthTag(), contenido]);
};

const descifrar = (paquete) => {
  const iv = paquete.subarray(0, IV);
  const tag = paquete.subarray(IV, IV + TAG);
  const descifrador = crypto.createDecipheriv(ALGORITMO, clave, iv);
  descifrador.setAuthTag(tag);
  return Buffer.concat([descifrador.update(paquete.subarray(IV + TAG)), descifrador.final()]);
};

const estaCifrado = (valor) => typeof valor === 'string' && valor.startsWith(PREFIJO_TEXTO);

const cifrarTexto = (texto) => {
  if (texto === null || texto === undefined || estaCifrado(texto)) return texto;
  return PREFIJO_TEXTO + cifrar(Buffer.from(texto, 'utf8')).toString('base64');
};

// Tolera texto sin cifrar (datos previos a la migración)
const descifrarTexto = (valor) => {
  if (!estaCifrado(valor)) return valor;
  return descifrar(Buffer.from(valor.slice(PREFIJO_TEXTO.length), 'base64')).toString('utf8');
};

const archivoCifrado = (buffer) => buffer.subarray(0, MARCA_ARCHIVO.length).equals(MARCA_ARCHIVO);

const cifrarArchivo = (buffer) => Buffer.concat([MARCA_ARCHIVO, cifrar(buffer)]);

const descifrarArchivo = (buffer) =>
  archivoCifrado(buffer) ? descifrar(buffer.subarray(MARCA_ARCHIVO.length)) : buffer;

module.exports = {
  cifrarTexto,
  descifrarTexto,
  estaCifrado,
  cifrarArchivo,
  descifrarArchivo,
  archivoCifrado,
};