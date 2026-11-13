package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sensorwave-dev/sensorwave/despachador"
	"github.com/sensorwave-dev/sensorwave/tipos"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Claims para el token JWT
type Claims struct {
	UserID  string `json:"user_id"`
	EsAdmin bool   `json:"es_admin"`
	jwt.RegisteredClaims
}

// UsuarioS3 representa un usuario almacenado en S3
type UsuarioS3 struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	EsAdmin      bool   `json:"esAdmin"`
	Eliminado    bool   `json:"eliminado,omitempty"`
}

// LoginRequest solicitud de login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse respuesta de login exitoso
type LoginResponse struct {
	Token   string      `json:"token"`
	Usuario UsuarioInfo `json:"usuario"`
}

// UsuarioInfo información del usuario (sin datos sensibles)
type UsuarioInfo struct {
	Username string `json:"username"`
	EsAdmin  bool   `json:"esAdmin"`
}

// CrearUsuarioRequest solicitud para crear usuario
type CrearUsuarioRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	EsAdmin  bool   `json:"esAdmin"`
}

// ActualizarUsuarioRequest solicitud para actualizar usuario
type ActualizarUsuarioRequest struct {
	Password *string `json:"password,omitempty"`
	EsAdmin  *bool   `json:"esAdmin,omitempty"`
}

var manager *despachador.GestorDespachador // variable global para manager
var s3Client *s3.Client                     // cliente S3 para usuarios
var s3Bucket string                         // bucket S3
var httpServer *http.Server                 // servidor HTTP

func main() {
	puerto := os.Getenv("PORT")
	if puerto == "" {
		puerto = "8080"
	}

	s3Bucket = os.Getenv("AWS_BUCKET")

	// configura el despachador
	configS3 := tipos.ConfiguracionS3{
		Endpoint:        os.Getenv("AWS_ENDPOINT"),
		Bucket:          s3Bucket,
		Region:          os.Getenv("AWS_REGION"),
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
	}

	// Crear cliente S3 para manejo de usuarios
	var err error
	s3Client, err = tipos.CrearClienteS3(configS3)
	if err != nil {
		log.Fatalf("Error creando cliente S3: %v", err)
	}

	// Verificar/crear usuarios por defecto
	if err := inicializarUsuarios(); err != nil {
		log.Printf("Advertencia al inicializar usuarios: %v", err)
	}

	if os.Getenv("SENSORWAVE_DESPACHADOR_ID") == "" {
		idReplica := os.Getenv("FLY_MACHINE_ID")
		if idReplica == "" {
			idReplica = os.Getenv("FLY_ALLOC_ID")
		}
		if idReplica != "" {
			if err := os.Setenv("SENSORWAVE_DESPACHADOR_ID", idReplica); err != nil {
				log.Fatalf("Error fijando SENSORWAVE_DESPACHADOR_ID: %v", err)
			}
		}
	}

	brokerMQTT := os.Getenv("BROKER_MQTT")
	if brokerMQTT == "" {
		brokerMQTT = "tcp://sensorwave-mqtt.internal:1884"
	}

	// crea el gestor del despachador
	manager, err = despachador.Crear(despachador.Opciones{
		ConfigS3:   configS3,
		BrokerMQTT: brokerMQTT,
	})
	if err != nil {
		log.Fatalf("Error creando despachador: %v", err)
	}
	// asegura el cierre del manager al finalizar
	defer manager.Cerrar()

	// Crear mux y configurar rutas con middlewares específicos
	mux := http.NewServeMux()

	// ============ RUTAS PÚBLICAS ============

	// /api/status - Estado del despachador
	mux.Handle("GET /api/status", despachador.HandlerStatus(manager))

	// /api/auth/login - Autenticación
	mux.Handle("POST /api/auth/login", http.HandlerFunc(handleLogin))

	// ============ RUTAS DEL DESPACHADOR (JWT) ============

	// /api/nodos - Listar nodos
	mux.Handle("GET /api/nodos", jwtMiddleware(despachador.HandlerListarNodos(manager)))

	// /api/series - Listar series (con query param ?patron=)
	mux.Handle("GET /api/series", jwtMiddleware(despachador.HandlerListarSeries(manager)))

	// /api/series/{path...} - Obtener serie específica
	mux.Handle("GET /api/series/{path...}", jwtMiddleware(despachador.HandlerObtenerSerie(manager)))

	// /api/consulta/* - Consultas de datos
	mux.Handle("POST /api/consulta/rango", jwtMiddleware(despachador.HandlerConsultarRango(manager)))
	mux.Handle("POST /api/consulta/ultimo", jwtMiddleware(despachador.HandlerConsultarUltimo(manager)))
	mux.Handle("POST /api/consulta/agregacion", jwtMiddleware(despachador.HandlerConsultarAgregacion(manager)))
	mux.Handle("POST /api/consulta/agregacion-temporal", jwtMiddleware(despachador.HandlerConsultarAgregacionTemporal(manager)))

	// Rutas para reglas
	mux.Handle("GET /api/reglas", jwtMiddleware(despachador.HandlerListarReglas(manager)))
	mux.Handle("GET /api/reglas/{id}", jwtMiddleware(despachador.HandlerObtenerRegla(manager)))
	mux.Handle("GET /api/nodos/{nodoID}/reglas", jwtMiddleware(despachador.HandlerListarReglasPorNodo(manager)))

	// ============ RUTAS PERSONALIZADAS (JWT) ============

	// /api/nodos/{nodo}/zonas
	mux.Handle("GET /api/nodos/{nodo}/zonas", jwtMiddleware(http.HandlerFunc(handleListarZonas)))

	// /api/nodos/{nodo}/zonas/{zona}/dispositivos
	mux.Handle("GET /api/nodos/{nodo}/zonas/{zona}/dispositivos", jwtMiddleware(http.HandlerFunc(handleListarDispositivosPorZona)))

	// /api/nodos/{nodo}/zonas/{zona}/dispositivos/{dispositivo}/sensores
	mux.Handle("GET /api/nodos/{nodo}/zonas/{zona}/dispositivos/{dispositivo}/sensores", jwtMiddleware(http.HandlerFunc(handleListarSensores)))

	// /api/nodos/{nodo}/zonas/{zona}/dispositivos/{dispositivo}/actuadores
	mux.Handle("GET /api/nodos/{nodo}/zonas/{zona}/dispositivos/{dispositivo}/actuadores", jwtMiddleware(http.HandlerFunc(handleListarActuadores)))

	// Rutas legacy (compatibilidad)
	mux.Handle("GET /api/nodos/{nodo}/dispositivos", jwtMiddleware(http.HandlerFunc(handleListarDispositivos)))
	mux.Handle("GET /api/nodos/{nodo}/dispositivos/{dispositivo}/mediciones", jwtMiddleware(http.HandlerFunc(handleListarMediciones)))

	// /api/usuarios/* - Gestión de usuarios
	mux.Handle("GET /api/usuarios", jwtMiddleware(http.HandlerFunc(handleListarUsuarios)))
	mux.Handle("GET /api/usuarios/{username}", jwtMiddleware(http.HandlerFunc(handleObtenerUsuario)))
	mux.Handle("POST /api/usuarios", jwtMiddleware(http.HandlerFunc(handleCrearUsuario)))
	mux.Handle("PUT /api/usuarios/{username}", jwtMiddleware(http.HandlerFunc(handleActualizarUsuario)))
	mux.Handle("DELETE /api/usuarios/{username}", jwtMiddleware(http.HandlerFunc(handleEliminarUsuario)))

	// ============ RUTA RAÍZ ============
	mux.Handle("GET /", http.HandlerFunc(handleInicio))

	// Aplicar CORS globalmente a todas las rutas
	handler := corsMiddleware(mux)

	// Crear servidor HTTP
	httpServer = &http.Server{
		Addr:         ":" + puerto,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// Arrancar servidor en goroutine
	go func() {
		log.Printf("API REST disponible en http://localhost:%s", puerto)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error iniciando servidor HTTP: %v", err)
		}
	}()

	log.Println("")
	log.Println("Servidor iniciado. Presione Ctrl+C para detener.")

	// Esperar señal de terminación
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Deteniendo servidor...")

	// Detener servidor HTTP gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Error deteniendo servidor: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	log.Println("Servidor finalizado.")
}

// inicializarUsuarios verifica si existe usuarios.json en S3 y lo crea si no existe
func inicializarUsuarios() error {
	ctx := context.Background()

	// Verificar si existe el archivo
	_, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String("usuarios.json"),
	})

	if err != nil {
		// El archivo no existe, crear con usuario por defecto
		log.Println("Creando usuarios.json con usuario admin por defecto...")

		// Generar hash de la contraseña "admin"
		hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("error generando hash: %v", err)
		}

		usuarios := []UsuarioS3{
			{
				Username:     "admin",
				PasswordHash: string(hash),
				EsAdmin:      true,
			},
		}

		// Serializar a JSON
		data, err := json.MarshalIndent(usuarios, "", "  ")
		if err != nil {
			return fmt.Errorf("error serializando usuarios: %v", err)
		}

		// Subir a S3
		_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      aws.String(s3Bucket),
			Key:         aws.String("usuarios.json"),
			Body:        bytes.NewReader(data),
			ContentType: aws.String("application/json"),
		})
		if err != nil {
			return fmt.Errorf("error subiendo usuarios.json a S3: %v", err)
		}

		log.Println("usuarios.json creado exitosamente con usuario admin/admin")
	}

	return nil
}

// cargarUsuarios lee usuarios.json desde S3
func cargarUsuarios() ([]UsuarioS3, error) {
	ctx := context.Background()

	result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String("usuarios.json"),
	})
	if err != nil {
		return nil, fmt.Errorf("error leyendo usuarios.json: %v", err)
	}
	defer result.Body.Close()

	data, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("error leyendo body: %v", err)
	}

	var usuarios []UsuarioS3
	if err := json.Unmarshal(data, &usuarios); err != nil {
		return nil, fmt.Errorf("error parseando JSON: %v", err)
	}

	return usuarios, nil
}

// guardarUsuarios guarda la lista de usuarios en S3
func guardarUsuarios(usuarios []UsuarioS3) error {
	ctx := context.Background()

	data, err := json.MarshalIndent(usuarios, "", "  ")
	if err != nil {
		return fmt.Errorf("error serializando usuarios: %v", err)
	}

	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s3Bucket),
		Key:         aws.String("usuarios.json"),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("error guardando usuarios.json: %v", err)
	}

	return nil
}

// obtenerClaimsDelToken extrae los claims del token JWT del header Authorization
func obtenerClaimsDelToken(r *http.Request) (*Claims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("sin header Authorization")
	}

	partes := strings.SplitN(authHeader, " ", 2)
	if len(partes) != 2 || !strings.EqualFold(partes[0], "bearer") {
		return nil, fmt.Errorf("formato de Authorization inválido")
	}

	tokenString := partes[1]
	claims := &Claims{}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "secret-key-default"
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("token inválido: %v", err)
	}

	return claims, nil
}

// handleListarUsuarios maneja GET /api/usuarios - Lista usuarios (solo admins)
func handleListarUsuarios(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Verificar que el usuario sea admin
	claims, err := obtenerClaimsDelToken(r)
	if err != nil || !claims.EsAdmin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Acceso denegado"})
		return
	}

	usuarios, err := cargarUsuarios()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error cargando usuarios"})
		return
	}

	// Filtrar: no mostrar admin ni eliminados
	var resultado []UsuarioInfo
	for _, u := range usuarios {
		if u.Username != "admin" && !u.Eliminado {
			resultado = append(resultado, UsuarioInfo{
				Username: u.Username,
				EsAdmin:  u.EsAdmin,
			})
		}
	}

	json.NewEncoder(w).Encode(resultado)
}

// handleObtenerUsuario maneja GET /api/usuarios/{username} - Obtiene un usuario
func handleObtenerUsuario(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Verificar que el usuario sea admin
	claims, err := obtenerClaimsDelToken(r)
	if err != nil || !claims.EsAdmin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Acceso denegado"})
		return
	}

	// Obtener username de la URL
	username := strings.TrimPrefix(r.URL.Path, "/api/usuarios/")
	if username == "" || username == "admin" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Usuario inválido"})
		return
	}

	usuarios, err := cargarUsuarios()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error cargando usuarios"})
		return
	}

	for _, u := range usuarios {
		if u.Username == username && !u.Eliminado {
			json.NewEncoder(w).Encode(UsuarioInfo{
				Username: u.Username,
				EsAdmin:  u.EsAdmin,
			})
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "Usuario no encontrado"})
}

// handleCrearUsuario maneja POST /api/usuarios - Crea un usuario
func handleCrearUsuario(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Verificar que el usuario sea admin
	claims, err := obtenerClaimsDelToken(r)
	if err != nil || !claims.EsAdmin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Acceso denegado"})
		return
	}

	// Leer body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error leyendo solicitud"})
		return
	}
	defer r.Body.Close()

	var req CrearUsuarioRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "JSON inválido"})
		return
	}

	// Validar campos
	if req.Username == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Usuario y contraseña son requeridos"})
		return
	}

	if req.Username == "admin" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "No se puede crear usuario con nombre 'admin'"})
		return
	}

	usuarios, err := cargarUsuarios()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error cargando usuarios"})
		return
	}

	// Verificar que no exista (incluyendo eliminados para evitar colisiones)
	for _, u := range usuarios {
		if u.Username == req.Username {
			if u.Eliminado {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "Este nombre de usuario ya fue utilizado"})
			} else {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{"error": "El usuario ya existe"})
			}
			return
		}
	}

	// Generar hash de la contraseña
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error procesando contraseña"})
		return
	}

	// Agregar usuario
	usuarios = append(usuarios, UsuarioS3{
		Username:     req.Username,
		PasswordHash: string(hash),
		EsAdmin:      req.EsAdmin,
		Eliminado:    false,
	})

	if err := guardarUsuarios(usuarios); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error guardando usuario"})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(UsuarioInfo{
		Username: req.Username,
		EsAdmin:  req.EsAdmin,
	})
}

// handleActualizarUsuario maneja PUT /api/usuarios/{username} - Actualiza un usuario
func handleActualizarUsuario(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Verificar que el usuario sea admin
	claims, err := obtenerClaimsDelToken(r)
	if err != nil || !claims.EsAdmin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Acceso denegado"})
		return
	}

	// Obtener username de la URL
	username := strings.TrimPrefix(r.URL.Path, "/api/usuarios/")
	if username == "" || username == "admin" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Usuario inválido"})
		return
	}

	// Leer body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error leyendo solicitud"})
		return
	}
	defer r.Body.Close()

	var req ActualizarUsuarioRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "JSON inválido"})
		return
	}

	usuarios, err := cargarUsuarios()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error cargando usuarios"})
		return
	}

	// Buscar y actualizar usuario
	encontrado := false
	for i, u := range usuarios {
		if u.Username == username && !u.Eliminado {
			encontrado = true

			if req.Password != nil && *req.Password != "" {
				hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{"error": "Error procesando contraseña"})
					return
				}
				usuarios[i].PasswordHash = string(hash)
			}

			if req.EsAdmin != nil {
				usuarios[i].EsAdmin = *req.EsAdmin
			}

			break
		}
	}

	if !encontrado {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Usuario no encontrado"})
		return
	}

	if err := guardarUsuarios(usuarios); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error guardando usuario"})
		return
	}

	// Buscar el usuario actualizado para devolverlo
	for _, u := range usuarios {
		if u.Username == username {
			json.NewEncoder(w).Encode(UsuarioInfo{
				Username: u.Username,
				EsAdmin:  u.EsAdmin,
			})
			return
		}
	}
}

// handleEliminarUsuario maneja DELETE /api/usuarios/{username} - Elimina un usuario (soft delete)
func handleEliminarUsuario(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Verificar que el usuario sea admin
	claims, err := obtenerClaimsDelToken(r)
	if err != nil || !claims.EsAdmin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Acceso denegado"})
		return
	}

	// Obtener username de la URL
	username := strings.TrimPrefix(r.URL.Path, "/api/usuarios/")
	if username == "" || username == "admin" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Usuario inválido"})
		return
	}

	usuarios, err := cargarUsuarios()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error cargando usuarios"})
		return
	}

	// Buscar y marcar como eliminado
	encontrado := false
	for i, u := range usuarios {
		if u.Username == username && !u.Eliminado {
			usuarios[i].Eliminado = true
			encontrado = true
			break
		}
	}

	if !encontrado {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Usuario no encontrado"})
		return
	}

	if err := guardarUsuarios(usuarios); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error guardando usuarios"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Usuario eliminado"})
}

// handleLogin maneja el endpoint POST /api/auth/login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Leer body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error leyendo solicitud"})
		return
	}
	defer r.Body.Close()

	// Parsear request
	var req LoginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "JSON inválido"})
		return
	}

	// Validar campos
	if req.Username == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Usuario y contraseña son requeridos"})
		return
	}

	// Cargar usuarios desde S3
	usuarios, err := cargarUsuarios()
	if err != nil {
		log.Printf("Error cargando usuarios: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error interno del servidor"})
		return
	}

	// Buscar usuario (no eliminado)
	var usuarioEncontrado *UsuarioS3
	for _, u := range usuarios {
		if u.Username == req.Username && !u.Eliminado {
			usuarioEncontrado = &u
			break
		}
	}

	if usuarioEncontrado == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Usuario o contraseña incorrectos"})
		return
	}

	// Verificar contraseña
	if err := bcrypt.CompareHashAndPassword([]byte(usuarioEncontrado.PasswordHash), []byte(req.Password)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Usuario o contraseña incorrectos"})
		return
	}

	// Generar JWT
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "secret-key-default" // Solo para desarrollo
	}

	claims := &Claims{
		UserID:  usuarioEncontrado.Username,
		EsAdmin: usuarioEncontrado.EsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)), // 7 días
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "huerta-iot",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		log.Printf("Error generando token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error generando token"})
		return
	}

	// Respuesta exitosa
	response := LoginResponse{
		Token: tokenString,
		Usuario: UsuarioInfo{
			Username: usuarioEncontrado.Username,
			EsAdmin:  usuarioEncontrado.EsAdmin,
		},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// corsMiddleware maneja los headers CORS y las peticiones OPTIONS (preflight)
func corsMiddleware(next http.Handler) http.Handler {
	log.Println("corsMiddleware: middleware creado")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf(">>> CORS: %s %s desde Origin=%s", r.Method, r.URL.Path, r.Header.Get("Origin"))

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Responder a peticiones preflight
		if r.Method == http.MethodOptions {
			log.Printf(">>> CORS: Respondiendo a OPTIONS preflight para %s", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			return
		}

		log.Printf(">>> CORS: Pasando al siguiente middleware para %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// jwtMiddleware verifica el token JWT en las solicitudes entrantes
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf(">>> JWT: %s %s", r.Method, r.URL.Path)

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Printf(">>> JWT: Sin header Authorization")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Se requiere encabezado de autorización"))
			return
		}

		partes := strings.SplitN(authHeader, " ", 2)
		if len(partes) != 2 || !strings.EqualFold(partes[0], "bearer") {
			log.Printf(">>> JWT: Formato de Authorization inválido")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Formato de encabezado de autorización no válido"))
			return
		}

		tokenString := partes[1]
		claims := &Claims{}

		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			jwtSecret = "secret-key-default" // Solo para desarrollo
		}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			log.Printf(">>> JWT: Token inválido: %v", err)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Token inválido"))
			return
		}

		log.Printf(">>> JWT: Token válido para usuario %s", claims.UserID)
		next.ServeHTTP(w, r)
	})
}

// parsePathUNS descompone un path de serie UNS en sus 5 segmentos.
// Formato esperado: {nodo_id}/{zona_id}/{dispositivo_id}/{tipo}/{metrica}
func parsePathUNS(path string) (nodo, zona, dispositivo, tipo, metrica string) {
	partes := strings.Split(path, "/")
	if len(partes) >= 5 {
		return partes[0], partes[1], partes[2], partes[3], partes[4]
	}
	return "", "", "", "", ""
}

// handleListarZonas maneja GET /api/nodos/{nodo}/zonas
func handleListarZonas(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	nodoID := r.PathValue("nodo")
	if nodoID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "ID de nodo requerido"})
		return
	}

	series := manager.ListarSeries(nodoID + "/*")

	zonasMap := make(map[string]struct{})
	for _, serie := range series {
		_, zona, _, _, _ := parsePathUNS(serie.Path)
		if zona != "" {
			zonasMap[zona] = struct{}{}
		}
	}

	zonas := make([]string, 0, len(zonasMap))
	for z := range zonasMap {
		zonas = append(zonas, z)
	}

	json.NewEncoder(w).Encode(zonas)
}

// handleListarDispositivos maneja GET /api/nodos/{nodo}/dispositivos
// Lista dispositivos de todas las zonas (flat) para compatibilidad.
func handleListarDispositivos(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	nodoID := r.PathValue("nodo")
	if nodoID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "ID de nodo requerido"})
		return
	}

	series := manager.ListarSeries(nodoID + "/*")

	dispositivosMap := make(map[string]struct{})
	for _, serie := range series {
		_, _, dispositivo, _, _ := parsePathUNS(serie.Path)
		if dispositivo != "" {
			dispositivosMap[dispositivo] = struct{}{}
		}
	}

	dispositivos := make([]string, 0, len(dispositivosMap))
	for d := range dispositivosMap {
		dispositivos = append(dispositivos, d)
	}

	json.NewEncoder(w).Encode(dispositivos)
}

// handleListarDispositivosPorZona maneja GET /api/nodos/{nodo}/zonas/{zona}/dispositivos
func handleListarDispositivosPorZona(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	nodoID := r.PathValue("nodo")
	zonaID := r.PathValue("zona")

	if nodoID == "" || zonaID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "ID de nodo y zona requeridos"})
		return
	}

	patron := nodoID + "/" + zonaID + "/*"
	series := manager.ListarSeries(patron)

	dispositivosMap := make(map[string]struct{})
	for _, serie := range series {
		_, zona, dispositivo, _, _ := parsePathUNS(serie.Path)
		if zona == zonaID && dispositivo != "" {
			dispositivosMap[dispositivo] = struct{}{}
		}
	}

	dispositivos := make([]string, 0, len(dispositivosMap))
	for d := range dispositivosMap {
		dispositivos = append(dispositivos, d)
	}

	json.NewEncoder(w).Encode(dispositivos)
}

// handleListarSensores maneja GET /api/nodos/{nodo}/zonas/{zona}/dispositivos/{dispositivo}/sensores
func handleListarSensores(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	nodoID := r.PathValue("nodo")
	zonaID := r.PathValue("zona")
	dispositivoID := r.PathValue("dispositivo")

	if nodoID == "" || zonaID == "" || dispositivoID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "ID de nodo, zona y dispositivo requeridos"})
		return
	}

	patron := nodoID + "/" + zonaID + "/" + dispositivoID + "/sensor/*"
	series := manager.ListarSeries(patron)

	sensores := make([]string, 0, len(series))
	for _, serie := range series {
		_, zona, dispositivo, tipo, metrica := parsePathUNS(serie.Path)
		if zona == zonaID && dispositivo == dispositivoID && tipo == "sensor" {
			sensores = append(sensores, metrica)
		}
	}

	json.NewEncoder(w).Encode(sensores)
}

// handleListarActuadores maneja GET /api/nodos/{nodo}/zonas/{zona}/dispositivos/{dispositivo}/actuadores
func handleListarActuadores(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	nodoID := r.PathValue("nodo")
	zonaID := r.PathValue("zona")
	dispositivoID := r.PathValue("dispositivo")

	if nodoID == "" || zonaID == "" || dispositivoID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "ID de nodo, zona y dispositivo requeridos"})
		return
	}

	patron := nodoID + "/" + zonaID + "/" + dispositivoID + "/actuador/*"
	series := manager.ListarSeries(patron)

	actuadores := make([]string, 0, len(series))
	for _, serie := range series {
		_, zona, dispositivo, tipo, metrica := parsePathUNS(serie.Path)
		if zona == zonaID && dispositivo == dispositivoID && tipo == "actuador" {
			actuadores = append(actuadores, metrica)
		}
	}

	json.NewEncoder(w).Encode(actuadores)
}

// handleListarMediciones maneja GET /api/nodos/{nodo}/dispositivos/{dispositivo}/mediciones
// DEPRECATED: mantiene compatibilidad con paths de 3 segmentos, ahora usa 5.
func handleListarMediciones(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	nodoID := r.PathValue("nodo")
	dispositivoID := r.PathValue("dispositivo")

	if nodoID == "" || dispositivoID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "ID de nodo y dispositivo requeridos"})
		return
	}

	patron := nodoID + "/*" + "/" + dispositivoID + "/*/*"
	series := manager.ListarSeries(patron)

	mediciones := make([]string, 0, len(series))
	for _, serie := range series {
		_, _, dispositivo, _, metrica := parsePathUNS(serie.Path)
		if dispositivo == dispositivoID && metrica != "" {
			mediciones = append(mediciones, metrica)
		}
	}

	json.NewEncoder(w).Encode(mediciones)
}

// handleInicio maneja las solicitudes a la ruta "/"
func handleInicio(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Huerta-Iot sirviendo en: %s", os.Getenv("FLY_REGION"))
}
