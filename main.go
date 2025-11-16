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

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

var (
	db         *sql.DB
	jwtSecret  []byte
	serverPort = "8080"

	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	clientsMu sync.Mutex

	// CLIENT STRUCT BARU
	clients = map[*Client]bool{}
)

// ====================
// CLIENT UNTUK WS
// ====================
type Client struct {
	conn   *websocket.Conn
	userID string // user_id dari JWT (sub)
}

// MODELS ==============================

type Room struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
	FullName string `json:"full_name"`
}

// HELPERS ==============================

func mustGetEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

func respondJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func respondError(w http.ResponseWriter, code int, msg string) {
	respondJSON(w, code, map[string]string{"error": msg})
}

// CORS =================================

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// JWT ==================================

func makeJWT(username, fullName string) (string, error) {
	claims := jwt.MapClaims{
		"sub":       username,
		"full_name": fullName,
		"exp":       time.Now().Add(24 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"role":      "admin",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func parseJWTFromRequest(r *http.Request) (string, string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", errors.New("missing Authorization header")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", "", errors.New("invalid Authorization format")
	}
	tokStr := parts[1]
	tok, err := jwt.Parse(tokStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil || !tok.Valid {
		return "", "", errors.New("invalid token")
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", errors.New("invalid claims")
	}
	username, _ := claims["sub"].(string)
	fullName, _ := claims["full_name"].(string)
	return username, fullName, nil
}

func requireAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := parseJWTFromRequest(r); err != nil {
			respondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// DATABASE INIT ========================

func initDB(ctx context.Context) error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL not set")
	}

	if !strings.Contains(dsn, "sslmode") {
		if strings.Contains(dsn, "?") {
			dsn = dsn + "&sslmode=require"
		} else {
			dsn = dsn + "?sslmode=require"
		}
	}

	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	db.SetMaxIdleConns(3)
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err = db.PingContext(ctx); err != nil {
		return err
	}

	log.Println("Connected to DB")

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

	_, _ = db.ExecContext(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT;`)

	var count int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE username='admin'`).Scan(&count)
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

// QUERIES ==============================

func getAllRooms(ctx context.Context) ([]Room, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, name, status FROM rooms ORDER BY id ASC`)
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

func updateRoomStatus(ctx context.Context, id int64, newStatus string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE rooms SET status=$1 WHERE id=$2`, newStatus, id)
	return err
}

func findUser(ctx context.Context, username string) (*User, error) {
	row := db.QueryRowContext(ctx,
		`SELECT id, username, password, full_name FROM users WHERE username=$1`, username)

	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Password, &u.FullName)
	return &u, err
}

// HANDLERS =============================

// POST /login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	u, err := findUser(r.Context(), body.Username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(body.Password)) != nil {
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := makeJWT(u.Username, u.FullName)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "token error")
		return
	}

	go func() {
		ip := readIP(r)
		ua := r.UserAgent()
		db.ExecContext(context.Background(),
			`INSERT INTO login_activities (username, ip, user_agent) VALUES ($1,$2,$3)`,
			u.Username, ip, ua)
	}()

	respondJSON(w, http.StatusOK, map[string]string{"token": token})
}

// GET /me
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

// POST /register
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

	if strings.TrimSpace(body.Username) == "" || strings.TrimSpace(body.Password) == "" {
		respondError(w, http.StatusBadRequest, "username/password required")
		return
	}

	var count int
	db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM users WHERE username=$1`, body.Username).Scan(&count)

	if count > 0 {
		respondError(w, http.StatusBadRequest, "username exists")
		return
	}

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

// POST /update-name
func handleUpdateName(w http.ResponseWriter, r *http.Request) {
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

	_, err = db.ExecContext(r.Context(),
		`UPDATE users SET full_name=$1 WHERE username=$2`,
		body.FullName, username)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "db error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "name updated"})
}

// POST /change-password
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

	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(body.OldPassword)) != nil {
		respondError(w, http.StatusBadRequest, "wrong old password")
		return
	}

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

// DELETE /delete-account
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

// GET /activities
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

// ROOMS =================================

func handleRooms(w http.ResponseWriter, r *http.Request) {
	rooms, err := getAllRooms(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db error")
		return
	}
	respondJSON(w, http.StatusOK, rooms)
}

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

	broadcastRooms(r.Context())
	respondJSON(w, http.StatusOK, map[string]string{"message": "updated"})
}

// ========================
//   HANDLE WS (BARU)
// ========================

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("ws upgrade:", err)
		return
	}

	client := &Client{conn: conn}

	clientsMu.Lock()
	clients[client] = true
	clientsMu.Unlock()

	// Kirim snapshot ruangan saat pertama connect
	writeRoomsSnapshot(r.Context(), conn)

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			clientsMu.Lock()
			delete(clients, client)
			clientsMu.Unlock()
			conn.Close()
			return
		}

		var msg map[string]any
		if json.Unmarshal(data, &msg) != nil {
			continue
		}

		// CLIENT AUTH: set user_id
		if msg["type"] == "auth" {
			if uid, ok := msg["user_id"].(string); ok {
				client.userID = uid
			}
			continue
		}

		// PROFILE UPDATE BROADCAST
		if msg["type"] == "notify_update_name" {
			fullName := msg["full_name"].(string)
			uid := msg["user_id"].(string)
			broadcastProfileUpdate(uid, fullName)
			continue
		}
	}
}

// SNAPSHOT ROOMS ========================

func writeRoomsSnapshot(ctx context.Context, conn *websocket.Conn) {
	rooms, _ := getAllRooms(ctx)
	b, _ := json.Marshal(map[string]any{"rooms": rooms})
	conn.WriteMessage(websocket.TextMessage, b)
}

// BROADCAST ROOMS =======================

func broadcastRooms(ctx context.Context) {
	rooms, _ := getAllRooms(ctx)
	b, _ := json.Marshal(map[string]any{"rooms": rooms})

	clientsMu.Lock()
	defer clientsMu.Unlock()

	for c := range clients {
		if err := c.conn.WriteMessage(websocket.TextMessage, b); err != nil {
			c.conn.Close()
			delete(clients, c)
		}
	}
}

// BROADCAST PROFILE NAME ================

func broadcastProfileUpdate(userID, newName string) {
	b, _ := json.Marshal(map[string]any{
		"type":      "profile_update",
		"full_name": newName,
	})

	clientsMu.Lock()
	defer clientsMu.Unlock()

	for c := range clients {
		if c.userID == userID {
			c.conn.WriteMessage(websocket.TextMessage, b)
		}
	}
}

// UTIL ================================

func readIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// MAIN =================================

func main() {
	godotenv.Load()

	jwtSecret = []byte(mustGetEnv("JWT_SECRET", "dev_secret"))
	if p := os.Getenv("PORT"); p != "" {
		serverPort = p
	}

	if err := initDB(context.Background()); err != nil {
		log.Fatal("DB init error:", err)
	}

	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/rooms", handleRooms)
	mux.HandleFunc("/ws", handleWS)

	// Protected
	mux.Handle("/me", requireAuth(handleMe))
	mux.Handle("/register", requireAuth(handleRegister))
	mux.Handle("/update-name", requireAuth(handleUpdateName))
	mux.Handle("/change-password", requireAuth(handleChangePassword))
	mux.Handle("/delete-account", requireAuth(handleDeleteAccount))
	mux.Handle("/activities", requireAuth(handleActivities))
	mux.Handle("/update", requireAuth(handleUpdateRoom))

	handler := withCORS(mux)

	log.Printf("✅ Backend running on :%s\n", serverPort)
	log.Fatal(http.ListenAndServe(":"+serverPort, handler))
}
