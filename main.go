package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	// Load environment variables dari file .env
	"github.com/joho/godotenv"

	// Driver PostgreSQL
	_ "github.com/lib/pq"

	// Library JWT untuk autentikasi
	"github.com/golang-jwt/jwt/v5"

	// Library WebSocket dari Gorilla
	"github.com/gorilla/websocket"

	// Library untuk hashing password
	"golang.org/x/crypto/bcrypt"
)

// ============================
//   VARIABEL GLOBAL SERVER
// ============================

var (
	db        *sql.DB  // Menyimpan koneksi database global
	jwtSecret []byte   // Menyimpan secret key untuk JWT
	serverPort = "8080" // Port server default

	// Upgrader digunakan untuk mengubah koneksi HTTP menjadi WebSocket
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// Mengizinkan semua origin (frontend dapat dari mana saja)
			return true
		},
	}

	// Mutex untuk mengamankan akses map clients (concurrent-safe)
	clientsMu sync.Mutex

	// Menyimpan seluruh client WebSocket yang sedang terhubung
	clients = map[*Client]bool{}
)

// ===========================================
//   STRUCT UNTUK WEBSOCKET DAN DATA DATABASE
// ===========================================

// Client merepresentasikan 1 koneksi WebSocket
type Client struct {
	conn   *websocket.Conn // Koneksi WebSocket
	userID string          // user_id dari JWT (opsional)
}

// Struktur untuk data ruangan
type Room struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Struktur untuk data user admin
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`        // Tidak dikembalikan ke client
	FullName string `json:"full_name"`
}

// ============================
//       FUNGSI BANTUAN
// ============================

// Mengambil environment variable,
// jika kosong maka menggunakan fallback
func mustGetEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

// Mengirim response JSON standar
func respondJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

// Mengirim error JSON
func respondError(w http.ResponseWriter, code int, msg string) {
	respondJSON(w, code, map[string]string{"error": msg})
}

// ============================
//              CORS
// ============================

// Middleware CORS untuk mengizinkan frontend mengakses API ini
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Mengizinkan semua origin (frontend domain apa saja boleh)
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// Header yang diperbolehkan
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		// Method yang diperbolehkan
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")

		// Menangani preflight request (OPTIONS)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Jika bukan OPTIONS, teruskan ke handler berikutnya
		next.ServeHTTP(w, r)
	})
}

// ============================
//        BAGIAN JWT
//   Membuat & memvalidasi token
// ============================

// Fungsi untuk membuat JWT saat user berhasil login
func makeJWT(username, fullName string) (string, error) {
	claims := jwt.MapClaims{
		"sub":       username,                 // subject → username
		"full_name": fullName,                 // nama lengkap user
		"exp":       time.Now().Add(24 * time.Hour).Unix(), // masa berlaku token (24 jam)
		"iat":       time.Now().Unix(),        // waktu token dibuat
		"role":      "admin",                  // role (opsional)
	}

	// Membuat token dengan metode HS256
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Menandatangani token dengan jwtSecret
	return token.SignedString(jwtSecret)
}

// Mengambil dan memvalidasi token JWT dari header Authorization
func parseJWTFromRequest(r *http.Request) (string, string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", errors.New("missing Authorization header")
	}

	// Format harus "Bearer tokenxxxx"
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", "", errors.New("invalid Authorization format")
	}

	tokStr := parts[1] // token string

	// Memvalidasi token
	tok, err := jwt.Parse(tokStr, func(token *jwt.Token) (interface{}, error) {
		// Memastikan metode sign adalah HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !tok.Valid {
		return "", "", errors.New("invalid token")
	}

	// Mengambil claims token
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", errors.New("invalid claims")
	}

	username, _ := claims["sub"].(string)
	fullName, _ := claims["full_name"].(string)

	return username, fullName, nil
}

// Middleware untuk endpoint yang membutuhkan autentikasi
func requireAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Jika token tidak valid → tolak
		if _, _, err := parseJWTFromRequest(r); err != nil {
			respondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		// Lanjut ke handler berikutnya
		next.ServeHTTP(w, r)
	})
}

// =====================================
//          INISIALISASI DATABASE
// =====================================

// Menghubungkan server ke PostgreSQL dan memastikan tabel tersedia
func initDB(ctx context.Context) error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL not set")
	}

	// Supabase memerlukan sslmode=require
	if !strings.Contains(dsn, "sslmode") {
		if strings.Contains(dsn, "?") {
			dsn += "&sslmode=require"
		} else {
			dsn += "?sslmode=require"
		}
	}

	var err error

	// Membuka koneksi ke PostgreSQL
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		return err
	}

	// Konfigurasi koneksi agar lebih stabil
	db.SetMaxIdleConns(3)
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)

	// Test koneksi
	if err = db.PingContext(ctx); err != nil {
		return err
	}

	log.Println("Connected to DB")

	// Membuat tabel jika belum tersedia
	_, err = db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS users (
	id SERIAL PRIMARY KEY,
	username TEXT UNIQUE NOT NULL,
	password TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rooms (
	id SERIAL PRIMARY KEY,
	name TEXT UNIQUE NOT NULL,
	status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_activities (
	id SERIAL PRIMARY KEY,
	username TEXT NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
	ip TEXT,
	user_agent TEXT
);
`)
	if err != nil {
		return err
	}

	// Menambahkan kolom full_name jika belum ada
	_, _ = db.ExecContext(ctx,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT;`)

	// SEEDING USER ADMIN

	var count int
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE username='admin'`).Scan(&count)

	if count == 0 {
		hashed, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		_, err = db.ExecContext(ctx,
			`INSERT INTO users (username, password, full_name) VALUES ($1,$2,$3)`,
			"admin", string(hashed), "Administrator")

		if err != nil {
			return err
		}

		log.Println("Seeded default admin: admin/admin123")
	}

	// SEEDING DATA RUANGAN

	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM rooms`).Scan(&count)

	if count == 0 {
		_, err = db.ExecContext(ctx, `
INSERT INTO rooms (name, status) VALUES
('Lab Komputer A','Tersedia'),
('Lab Komputer B','Digunakan'),
('Ruang Multimedia','Dipesan')
`)
		if err != nil {
			return err
		}

		log.Println("Seeded default rooms")
	}

	return nil
}

// ============================
//           QUERIES
//  Fungsi untuk mengambil/mengubah data
// ============================

// Mengambil seluruh data ruangan
func getAllRooms(ctx context.Context) ([]Room, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, status FROM rooms ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Room

	for rows.Next() {
		var r Room
		rows.Scan(&r.ID, &r.Name, &r.Status)
		out = append(out, r)
	}

	return out, nil
}

// Mengubah status ruangan tertentu
func updateRoomStatus(ctx context.Context, id int64, newStatus string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE rooms SET status=$1 WHERE id=$2`,
		newStatus, id)
	return err
}

// Mencari user berdasarkan username
func findUser(ctx context.Context, username string) (*User, error) {
	row := db.QueryRowContext(ctx,
		`SELECT id, username, password, full_name FROM users WHERE username=$1`,
		username)

	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Password, &u.FullName)

	return &u, err
}

// ======================================
//          HANDLER UNTUK AUTH
//      Login, Profil, dll.
// ======================================

// Handler untuk melakukan login
// Mengembalikan JWT jika username & password benar
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Membaca JSON dari body request
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	// Mencari user berdasarkan username
	u, err := findUser(r.Context(), body.Username)

	// Jika tidak ditemukan atau password salah → gagal login
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(body.Password)) != nil {
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Membuat JWT untuk session login
	token, err := makeJWT(u.Username, u.FullName)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "token error")
		return
	}

	// Menyimpan aktivitas login ke database (background)
	go func() {
		ip := readIP(r)
		ua := r.UserAgent()
		db.ExecContext(context.Background(),
			`INSERT INTO login_activities (username, ip, user_agent) VALUES ($1,$2,$3)`,
			u.Username, ip, ua)
	}()

	respondJSON(w, http.StatusOK, map[string]string{"token": token})
}


// Handler untuk mengambil data diri user berdasarkan token JWT
func handleMe(w http.ResponseWriter, r *http.Request) {
	username, fullName, err := parseJWTFromRequest(r)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"username":  username,
		"full_name": fullName,
	})
}


// Handler untuk mendaftarkan pengguna baru (khusus admin yang sudah login)
func handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		FullName string `json:"full_name"`
	}

	if json.NewDecoder(r.Body).Decode(&body) != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	// Validasi input sederhana
	if strings.TrimSpace(body.Username) == "" || strings.TrimSpace(body.Password) == "" {
		respondError(w, http.StatusBadRequest, "username/password required")
		return
	}

	// Mengecek apakah username sudah ada
	var count int
	db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM users WHERE username=$1`, body.Username).Scan(&count)

	if count > 0 {
		respondError(w, http.StatusBadRequest, "username exists")
		return
	}

	// Hash password sebelum disimpan
	hashed, _ := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)

	_, err := db.ExecContext(r.Context(),
		`INSERT INTO users (username, password, full_name) VALUES ($1,$2,$3)`,
		body.Username, string(hashed), body.FullName)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "db error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "registered"})
}


// Handler untuk memperbarui nama lengkap pengguna
func handleUpdateName(w http.ResponseWriter, r *http.Request) {

	// Mendapatkan username dari token
	username, _, err := parseJWTFromRequest(r)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	var body struct {
		FullName string `json:"full_name"`
	}

	if json.NewDecoder(r.Body).Decode(&body) != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	// Update nama di database
	_, err = db.ExecContext(r.Context(),
		`UPDATE users SET full_name=$1 WHERE username=$2`,
		body.FullName, username)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "db error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "name updated"})
}


// Handler untuk mengubah password pengguna
func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	username, _, err := parseJWTFromRequest(r)

	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	json.NewDecoder(r.Body).Decode(&body)

	u, err := findUser(r.Context(), username)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db error")
		return
	}

	// Validasi password lama
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(body.OldPassword)) != nil {
		respondError(w, http.StatusBadRequest, "wrong old password")
		return
	}

	// Hash password baru
	hashed, _ := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)

	_, err = db.ExecContext(r.Context(),
		`UPDATE users SET password=$1 WHERE username=$2`,
		string(hashed), username)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "db error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "password changed"})
}


// Handler untuk menghapus akun
func handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	username, _, err := parseJWTFromRequest(r)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	_, err = db.ExecContext(r.Context(),
		`DELETE FROM users WHERE username=$1`, username)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "db error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "account deleted"})
}


// Handler untuk mengambil riwayat aktivitas login user
func handleActivities(w http.ResponseWriter, r *http.Request) {

	username, _, err := parseJWTFromRequest(r)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	rows, err := db.QueryContext(r.Context(),
		`SELECT id, created_at, ip, user_agent
		   FROM login_activities
		  WHERE username=$1
		  ORDER BY created_at DESC
		  LIMIT 50`, username)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "db error")
		return
	}

	defer rows.Close()

	// Struktur untuk menampung hasil query
	type act struct {
		ID        int64     `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		IP        string    `json:"ip"`
		UserAgent string    `json:"user_agent"`
	}

	var out []act

	for rows.Next() {
		var a act
		rows.Scan(&a.ID, &a.CreatedAt, &a.IP, &a.UserAgent)
		out = append(out, a)
	}

	respondJSON(w, http.StatusOK, out)
}

// ======================================
//          HANDLER UNTUK ROOMS
// ======================================

// Mengambil seluruh ruangan (public)
func handleRooms(w http.ResponseWriter, r *http.Request) {
	rooms, err := getAllRooms(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db error")
		return
	}
	respondJSON(w, http.StatusOK, rooms)
}


// Mengupdate status ruangan (khusus admin)
// Setelah update → broadcast ke semua WebSocket agar realtime
func handleUpdateRoom(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID     int64  `json:"id"`
		Status string `json:"status"`
	}

	_ = json.NewDecoder(r.Body).Decode(&body)

	if err := updateRoomStatus(r.Context(), body.ID, body.Status); err != nil {
		respondError(w, http.StatusInternalServerError, "db error")
		return
	}

	// Broadcast ke seluruh client WebSocket
	broadcastRooms(r.Context())

	respondJSON(w, http.StatusOK, map[string]string{"message": "updated"})
}

// =========================================
//           HANDLER UNTUK WEBSOCKET
//    Mengelola koneksi realtime antar client
// =========================================

func handleWS(w http.ResponseWriter, r *http.Request) {

	// Mengubah koneksi HTTP menjadi WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("ws upgrade:", err)
		return
	}

	// Membuat client baru
	client := &Client{conn: conn}

	// Menyimpan client ke daftar koneksi
	clientsMu.Lock()
	clients[client] = true
	clientsMu.Unlock()

	// Mengirim snapshot data ruangan ketika client pertama kali terhubung
	writeRoomsSnapshot(r.Context(), conn)

	// Loop membaca pesan dari client
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			// Jika client disconnect → hapus dari daftar
			clientsMu.Lock()
			delete(clients, client)
			clientsMu.Unlock()

			conn.Close()
			return
		}

		// Pesan dari client dalam bentuk JSON → parse menjadi map
		var msg map[string]any
		if json.Unmarshal(data, &msg) != nil {
			continue // bila format salah → lewati
		}

		// Client mengirim data autentikasi (opsional)
		if msg["type"] == "auth" {
			if uid, ok := msg["user_id"].(string); ok {
				client.userID = uid
			}
			continue
		}

		// Broadcast perubahan nama profil (khusus user terkait)
		if msg["type"] == "notify_update_name" {
			fullName := msg["full_name"].(string)
			uid := msg["user_id"].(string)
			broadcastProfileUpdate(uid, fullName)
			continue
		}
	}
}

// =========================================
//    FUNGSI PENDUKUNG UNTUK WEBSOCKET
// =========================================

// Mengirim snapshot (data lengkap) ruangan ke 1 client saja
func writeRoomsSnapshot(ctx context.Context, conn *websocket.Conn) {
	rooms, _ := getAllRooms(ctx)

	// Format kirim: {"rooms": [...]}
	b, _ := json.Marshal(map[string]any{"rooms": rooms})

	conn.WriteMessage(websocket.TextMessage, b)
}

// Mengirim update ruangan ke *semua* client WebSocket
func broadcastRooms(ctx context.Context) {
	rooms, _ := getAllRooms(ctx)
	b, _ := json.Marshal(map[string]any{"rooms": rooms})

	clientsMu.Lock()
	defer clientsMu.Unlock()

	// Mengirim pesan ke semua client
	for c := range clients {
		if err := c.conn.WriteMessage(websocket.TextMessage, b); err != nil {
			// Jika gagal kirim (client mati) → hapus
			c.conn.Close()
			delete(clients, c)
		}
	}
}

// Mengirim update profile (nama user) hanya kepada client tertentu
func broadcastProfileUpdate(userID, newName string) {
	b, _ := json.Marshal(map[string]any{
		"type":      "profile_update",
		"full_name": newName,
	})

	clientsMu.Lock()
	defer clientsMu.Unlock()

	for c := range clients {
		// Broadcast hanya untuk user yang sesuai
		if c.userID == userID {
			c.conn.WriteMessage(websocket.TextMessage, b)
		}
	}
}

// =========================================
//         FUNGSI UTIL MENENTUKAN IP
// =========================================

// Mengambil IP asli client, baik direct maupun lewat proxy seperti Vercel
func readIP(r *http.Request) string {

	// Jika ada header X-Forwarded-For → gunakan itu
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Jika tidak, pakai RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// =========================================
//           FUNGSI main() SERVER
// =========================================

func main() {

	// Memuat file .env (jika ada)
	godotenv.Load()

	// Mengambil JWT_SECRET dari environment (atau default)
	jwtSecret = []byte(mustGetEnv("JWT_SECRET", "dev_secret"))

	// Mengambil PORT dari render/vercel (jika ada)
	if p := os.Getenv("PORT"); p != "" {
		serverPort = p
	}

	// Inisialisasi database
	if err := initDB(context.Background()); err != nil {
		log.Fatal("DB init error:", err)
	}

	// Router HTTP standar
	mux := http.NewServeMux()

	//
	// ROUTE PUBLIC
	//
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/rooms", handleRooms)
	mux.HandleFunc("/ws", handleWS)

	// ROUTE PROTECTED (HARUS PAKAI JWT)
	mux.Handle("/me", requireAuth(handleMe))
	mux.Handle("/register", requireAuth(handleRegister))
	mux.Handle("/update-name", requireAuth(handleUpdateName))
	mux.Handle("/change-password", requireAuth(handleChangePassword))
	mux.Handle("/delete-account", requireAuth(handleDeleteAccount))
	mux.Handle("/activities", requireAuth(handleActivities))
	mux.Handle("/update", requireAuth(handleUpdateRoom))

	// Membungkus semua route dengan middleware CORS
	handler := withCORS(mux)

	log.Printf("✅ Backend running on :%s\n", serverPort)

	// Menjalankan server HTTP
	log.Fatal(http.ListenAndServe(":"+serverPort, handler))
}
