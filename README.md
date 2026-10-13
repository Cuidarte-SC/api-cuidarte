# api-cuidarte

API REST de **Cuidarte+**, el sistema de exámenes médicos del Caso B (ISY1102). Está construida con Node.js 20, Express 5 y PostgreSQL.

**Versión bajo prueba EP02:** `v1.1.0`.

## Cómo levantarla

La API se levanta desde el repo `infra-cuidarte`, que debe estar como carpeta hermana:

```bash
cd ../infra-cuidarte
docker compose --profile app up -d --build api
curl http://localhost:4000/api/salud
```

Requiere en el `.env` de `infra-cuidarte` las variables `JWT_SECRET` y `DATA_ENCRYPTION_KEY` (64 caracteres hexadecimales cada una). Si falta alguna o no tiene el formato correcto, la API no arranca.

Documentación interactiva: **http://localhost:4000/api/docs** (Swagger UI) y especificación en `docs/openapi.yaml`. Por https://localhost:8443 la página de Swagger no carga, porque la CSP estricta de nginx bloquea sus estilos en línea.

## Seguridad implementada

| Control | Implementación | Requerimiento |
|---|---|---|
| Autenticación | JWT HS256 en `Authorization: Bearer`, vigencia 15 min | RF-1, NFR-SEG-9 |
| Cierre de sesión | El `jti` del token queda en `token_revocado` y todos los refresh tokens del usuario se revocan | RF-1.2 |
| Renovación de sesión | Refresh token opaco de 8 h, guardado solo como hash SHA-256, con rotación en cada uso | RF-1.2 |
| Contraseñas | bcrypt costo 12; política de 12+ caracteres con mayúscula, minúscula, número y símbolo | NFR-SEG-2 |
| RBAC | Middleware `requerirRol` en el backend; el rol se lee de la BD, no del token | NFR-SEG-4 |
| Acceso a datos propios | Un paciente solo ve su ficha, sus exámenes y sus documentos (403 en lo ajeno) | RB-1 |
| SQL Injection | Consultas parametrizadas y lista blanca de columnas en el UPDATE | NFR-SEG-5 |
| XSS | Solo responde JSON; validación de entrada server-side | NFR-SEG-5 |
| CSRF | No aplica: la sesión va en el header, no en cookies | NFR-SEG-5 |
| Fuerza bruta | 10 intentos de login cada 15 min por IP (429); 5 registros por hora por IP | NFR-SEG |
| Cifrado en reposo | AES-256-GCM para `examen.resultado` y los archivos de documentos; clave en `DATA_ENCRYPTION_KEY` | NFR-SEG-3 |
| Cabeceras | helmet (nosniff, HSTS, CSP, sin `X-Powered-By`) | OWASP |
| Archivos | Tipo validado por *magic bytes*, máximo 10 MB, nombre en disco generado por el servidor | RF-4 |
| Auditoría | LOGIN, LOGIN_FALLIDO, LOGOUT, READ, CREATE, UPDATE, DELETE, DESCARGA y ACCESO_DENEGADO | RF-5, NFR-SEG-6 |
| Logs | Sin cuerpos ni tokens; nunca se registran contraseñas | NFR-SEG-6 |
| Contenedor | Corre como usuario `node` (no root) | Mínimo privilegio |

## Cambios v1.1.0

- **RF-1.2** Refresh token con rotación (8 h); el logout revoca todas las sesiones.
- **RF-2.1** Autoregistro con rol paciente (`POST /api/auth/registro`).
- **RF-2.3** Edición de pacientes (`PUT /api/pacientes/:id`).
- **RF-2.5 a 2.7** Gestión de usuarios por el administrador (`/api/usuarios`).
- **RF-3.3** Eliminación lógica de exámenes y documentos.
- **RF-4.3** Un documento activo por examen; subir otro lo reemplaza como nueva versión.
- **NFR-SEG-3** Cifrado en reposo AES-256-GCM de resultados de exámenes y archivos.
- **ERS 3.1.2** Especificación OpenAPI en `docs/openapi.yaml` y Swagger UI en `/api/docs`.

## Riesgos residuales conocidos

- **Datos de identificación sin cifrar**: nombre, RUT y correo del paciente no se cifran, para mantener la búsqueda. En producción se mitiga con cifrado de disco del servidor de BD.
- **Gestión de la clave**: `DATA_ENCRYPTION_KEY` está en el `.env`. En producción debe ir en un gestor de secretos con rotación. Si la clave se pierde, los datos cifrados no se pueden recuperar.
- **TLS interno (NFR-SEG-1)**: TLS se termina en nginx; el tráfico nginx → API → BD dentro de la red Docker va sin cifrar.
- **Integración de correo (ERS 2.5)**: el registro no envía correo de confirmación.
- **Respaldos (NFR-SEG-7)**: los scripts de `infra-cuidarte/scripts` respaldan BD y documentos, pero se ejecutan a mano; no hay respaldo diario programado.

## Endpoints

| Método | Ruta | Roles | Respuesta |
|---|---|---|---|
| GET | `/api/salud` | público | 200 / 503 |
| GET | `/api/docs` · `/api/openapi.yaml` | público | Swagger UI · especificación |
| POST | `/api/auth/login` | público | 200 token + refresh · 401 · 429 |
| POST | `/api/auth/registro` | público | 201 (rol paciente) · 400 · 409 · 429 |
| POST | `/api/auth/refresh` | público (con refresh token) | 200 · 401 |
| POST | `/api/auth/logout` | autenticado | 204 |
| GET | `/api/auth/me` | autenticado | 200 |
| GET | `/api/usuarios?q=&rol=` | admin | 200 |
| GET · PUT · DELETE | `/api/usuarios/:id` | admin | 200 · 204 · 400 · 404 · 409 |
| GET | `/api/pacientes?q=&pagina=&limite=` | admin, medico | 200 |
| POST | `/api/pacientes` | admin, medico | 201 · 400 · 409 |
| GET | `/api/pacientes/:id` | admin, medico, paciente (propio) | 200 · 403 · 404 |
| PUT | `/api/pacientes/:id` | admin, medico | 200 · 400 · 404 · 409 |
| DELETE | `/api/pacientes/:id` | admin (eliminación lógica) | 204 |
| GET | `/api/pacientes/:id/examenes` | admin, medico, paciente (propio) | 200 · 403 |
| POST | `/api/pacientes/:id/examenes` | admin, medico | 201 |
| GET | `/api/pacientes/:id/examenes/:examenId` | admin, medico, paciente (propio) | 200 · 404 |
| PUT | `/api/pacientes/:id/examenes/:examenId` | admin, medico | 200 |
| DELETE | `/api/pacientes/:id/examenes/:examenId` | admin, medico (eliminación lógica) | 204 |
| POST | `/api/examenes/:examenId/documentos` (multipart `archivo`) | admin, medico | 201 · 413 · 415 |
| GET | `/api/examenes/:examenId/documentos` | admin, medico, paciente (propio) | 200 |
| GET | `/api/documentos/:id/descarga` | admin, medico, paciente (propio) | 200 · 403 · 404 |
| DELETE | `/api/documentos/:id` | admin, medico (eliminación lógica) | 204 |
| GET | `/api/auditoria?paciente_id=&usuario_id=&accion=&limite=` | admin | 200 |

### Ejemplo: registrar un paciente con cuenta de acceso

```json
POST /api/pacientes
Authorization: Bearer <token de médico>

{
  "nombre": "Juan Pérez García",
  "rut": "18.765.432-7",
  "correo": "juan.perez@mail.com",
  "fecha_nacimiento": "1962-05-15",
  "consentimiento_datos": true,
  "credenciales": { "nombre_usuario": "juan.perez", "password": "Paciente#2026x" }
}
```

El rol de la cuenta creada siempre es `paciente`: el servidor ignora cualquier rol enviado por el cliente.

## Análisis estático

Con Node instalado:

```bash
npm install
npm run lint                         # ESLint + eslint-plugin-security
npm run lint:json                    # genera eslint-report.json
npm audit                            # dependencias con CVE
```

Sin Node, con Docker (PowerShell):

```powershell
docker run --rm -v "${PWD}:/app" -w /app node:20-alpine sh -c "npm ci --no-audit && npx eslint ."
docker run --rm -v "${PWD}:/app" -w /app node:20-alpine npm audit
```
