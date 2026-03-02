# Huerta IoT Backend

Backend en Go para el sistema de monitoreo de series temporales Huerta IoT.

## Requisitos

- Go 1.24+
- Cuenta AWS S3 (o compatible)

## Instalación

```bash
# Descargar dependencias
go mod download
```

## Desarrollo

```bash
# Iniciar servidor
go run main.go
```

El servidor estará disponible en `http://localhost:8080`

## Build para producción

```bash
# Compilar
go build -o huerta-iot-backend

# Ejecutar
./huerta-iot-backend
```

## Configuración

### Variables de entorno

```env
# Puerto del servidor (default: 8080)
PORT=8080

# AWS S3 - Almacenamiento de datos
AWS_BUCKET=mi-bucket
AWS_ENDPOINT=https://s3.amazonaws.com
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=tu-access-key
AWS_SECRET_ACCESS_KEY=tu-secret-key

# JWT - Autenticación (opcional, tiene default)
JWT_SECRET=tu-secreto-jwt
```

## API Endpoints

### Públicos

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/status` | GET | Estado del despachador |
| `/api/auth/login` | POST | Autenticación (devuelve JWT) |

### Autenticados (requieren JWT)

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/nodos` | GET | Listar nodos |
| `/api/series` | GET | Listar series (query: `?patron=`) |
| `/api/series/{path...}` | GET | Obtener serie específica |
| `/api/consulta/rango` | POST | Consultar rango de datos |
| `/api/consulta/ultimo` | POST | Último punto de la serie |
| `/api/consulta/agregacion` | POST | Agregación simple |
| `/api/consulta/agregacion-temporal` | POST | Agregación temporal |
| `/api/reglas` | GET | Listar reglas |
| `/api/reglas/{id}` | GET | Obtener regla específica |
| `/api/nodos/{nodoID}/reglas` | GET | Reglas por nodo |
| `/api/nodos/{nodo}/dispositivos` | GET | Dispositivos por nodo |
| `/api/nodos/{nodo}/dispositivos/{dispositivo}/mediciones` | GET | Mediciones por dispositivo |

### Usuarios (solo admins)

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/usuarios` | GET | Listar usuarios |
| `/api/usuarios/{username}` | GET | Obtener usuario |
| `/api/usuarios` | POST | Crear usuario |
| `/api/usuarios/{username}` | PUT | Actualizar usuario |
| `/api/usuarios/{username}` | DELETE | Eliminar usuario (soft delete) |

### Autenticación

Los endpoints protegidos requieren header:
```
Authorization: Bearer <token-jwt>
```

## Despliegue

### Docker

```bash
# Construir imagen
docker build -t huerta-iot-backend .

# Ejecutar contenedor
docker run -p 8080:8080 --env-file .env huerta-iot-backend
```

### Fly.io

```bash
# Desplegar
fly deploy
```

## Tecnologías

- **Go 1.24** - Lenguaje
- **SensorWave** - Librería de series temporales
- **JWT** - Autenticación
- **AWS S3** - Persistencia
- **bcrypt** - Hash de contraseñas
