// Validaciones de entrada server-side (NFR-SEG-5). Nunca se confía en el frontend.

class ErrorHttp extends Error {
  constructor(status, mensaje) {
    super(mensaje);
    this.status = status;
  }
}

// Dígito verificador del RUT chileno (módulo 11)
const calcularDv = (numero) => {
  let suma = 0;
  let multiplicador = 2;
  for (let n = numero; n > 0; n = Math.floor(n / 10)) {
    suma += (n % 10) * multiplicador;
    multiplicador = multiplicador === 7 ? 2 : multiplicador + 1;
  }
  const resto = 11 - (suma % 11);
  if (resto === 11) return '0';
  if (resto === 10) return 'K';
  return String(resto);
};

// Formato exigido: XX.XXX.XXX-D
const FORMATO_RUT = /^\d{1,2}\.\d{3}\.\d{3}-[\dK]$/;

const rutValido = (rut) => {
  if (typeof rut !== 'string' || !FORMATO_RUT.test(rut)) return false;
  const [cuerpo, dv] = rut.split('-');
  return calcularDv(Number(cuerpo.replace(/\./g, ''))) === dv;
};

const FORMATO_CORREO = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const correoValido = (correo) =>
  typeof correo === 'string' && correo.length <= 120 && FORMATO_CORREO.test(correo);

const FORMATO_FECHA = /^\d{4}-\d{2}-\d{2}$/;
const fechaValida = (fecha) =>
  typeof fecha === 'string' && FORMATO_FECHA.test(fecha) && !Number.isNaN(Date.parse(fecha));

// Contraseña: 12+ caracteres, mayúscula, minúscula, número y símbolo
const passwordRobusta = (password) =>
  typeof password === 'string' &&
  password.length >= 12 &&
  password.length <= 72 && // límite de bcrypt
  /[A-Z]/.test(password) &&
  /[a-z]/.test(password) &&
  /\d/.test(password) &&
  /[^A-Za-z0-9]/.test(password);

const textoRequerido = (valor, campo, max) => {
  if (typeof valor !== 'string' || valor.trim().length === 0) {
    throw new ErrorHttp(400, `El campo "${campo}" es obligatorio`);
  }
  if (valor.length > max) {
    throw new ErrorHttp(400, `El campo "${campo}" supera ${max} caracteres`);
  }
  return valor.trim();
};

const idValido = (valor) => {
  const n = Number(valor);
  if (!Number.isInteger(n) || n <= 0 || n > 2147483647) {
    throw new ErrorHttp(400, 'Identificador inválido');
  }
  return n;
};

module.exports = {
  ErrorHttp,
  calcularDv,
  rutValido,
  correoValido,
  fechaValida,
  passwordRobusta,
  textoRequerido,
  idValido,
};
