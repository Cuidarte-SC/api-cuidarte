# api-cuidarte

API REST de **Cuidarte+**, el sistema de exámenes médicos del Caso B (ISY1102). Está construida con Node.js 20, Express 5 y PostgreSQL.

## Cómo levantarla

La API se levanta desde el repo `infra-cuidarte`, que debe estar como carpeta hermana:

```bash
cd ../infra-cuidarte
docker compose --profile app up -d --build api
curl http://localhost:4000/api/salud
```

## Seguridad implementada

| Control | Implementación | Requerimiento |
|---|---|---|
| Autenticación | JWT HS256 en `Authorization: Bearer`, vigencia 15 min | RF-1, NFR-SEG-9 |
| Cierre de sesión | El `jti` del token queda en `token_revocado` y es rechazado | RF-1 |
| Contraseñas | bcrypt costo 12; política de 12+ caracteres con mayúscula, minúscula, número y símbolo | NFR-SEG-2 |
| RBAC | Middleware `requerirRol` en el backend; el rol se lee de la BD, no del token | NFR-SEG-4 |
| Acceso a datos propios | Un paciente solo ve su ficha, sus exámenes y sus documentos (403 en lo ajeno) | RB-1 |
| SQL Injection | Consultas parametrizadas y lista blanca de columnas en el UPDATE | NFR-SEG-5 |
| XSS | Solo responde JSON; validación de entrada server-side | NFR-SEG-5 |
| CSRF | No aplica: la sesión va en el header, no en cookies | NFR-SEG-5 |
| Fuerza bruta | 10 intentos de login cada 15 min por IP (429) | NFR-SEG |
| Cabeceras | helmet (nosniff, HSTS, CSP, sin `X-Powered-By`) | OWASP |
| Archivos | Tipo validado por *magic bytes*, máximo 10 MB, nombre en disco generado por el servidor | RF-4 |
| Auditoría | LOGIN, LOGIN_FALLIDO, LOGOUT, READ, CREATE, UPDATE, DELETE, DESCARGA y ACCESO_DENEGADO | RF-5, NFR-SEG-6 |
| Logs | Sin cuerpos ni tokens; nunca se registran contraseñas | NFR-SEG-6 |
| Contenedor | Corre como usuario `node` (no root) | Mínimo privilegio |

## Pendientes conocidos (v1.0)

Estas brechas son reales y deben evaluarse en la ejecución de pruebas:

- **NFR-SEG-3, cifrado en reposo**: los datos de pacientes y exámenes **no** están cifrados a nivel de columna.
- **NFR-SEG-9, refresh token**: no implementado. Al expirar los 15 minutos, el usuario debe volver a iniciar sesión.
- **NFR-SEG-1, TLS**: la API escucha en HTTP dentro de la red Docker. TLS se termina en el frontend (nginx).

## Endpoints

| Método | Ruta | Roles | Respuesta |
|---|---|---|---|
| GET | `/api/salud` | público | 200 / 503 |
| POST | `/api/auth/login` | público | 200 token · 401 · 429 |
| POST | `/api/auth/logout` | autenticado | 204 |
| GET | `/api/auth/me` | autenticado | 200 |
| GET | `/api/pacientes?q=&pagina=&limite=` | admin, medico | 200 |
| POST | `/api/pacientes` | admin, medico | 201 · 400 · 409 |
| GET | `/api/pacientes/:id` | admin, medico, paciente (propio) | 200 · 403 · 404 |
| DELETE | `/api/pacientes/:id` | admin (eliminación lógica) | 204 |
| GET | `/api/pacientes/:id/examenes` | admin, medico, paciente (propio) | 200 · 403 |
| POST | `/api/pacientes/:id/examenes` | admin, medico | 201 |
| GET | `/api/pacientes/:id/examenes/:examenId` | admin, medico, paciente (propio) | 200 |
| PUT | `/api/pacientes/:id/examenes/:examenId` | admin, medico | 200 |
| POST | `/api/examenes/:examenId/documentos` (multipart `archivo`) | admin, medico | 201 · 413 · 415 |
| GET | `/api/examenes/:examenId/documentos` | admin, medico, paciente (propio) | 200 |
| GET | `/api/documentos/:id/descarga` | admin, medico, paciente (propio) | 200 · 403 |
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

```bash
npm install
npm run lint                         # ESLint + eslint-plugin-security
npm run lint:json                    # genera eslint-report.json
npm audit                            # dependencias con CVE
npm audit --json > audit-report.json
```
