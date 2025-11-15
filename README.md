# 🏫 RoomWatch – Realtime Room Monitoring

### 🔗 Demo Online  
👉 **https://realtime-room-monitoring.vercel.app/**

Aplikasi monitoring status ruangan kampus secara **Realtime** menggunakan WebSocket.  
User dapat melihat status ruangan, dan admin dapat mengelola ruangan melalui dashboard khusus.

---

## 👥 Anggota Kelompok

| Nama                            | NIM          |
|---------------------------------|--------------|
| **Nathanael Christian Perkasa** | 213400010    |
| **Maria Chatrin Bunaen**        | *(isi NIM lengkap di sini)* |

---

## 📖 Deskripsi Aplikasi

**RoomWatch** adalah aplikasi web untuk memantau status ruangan kampus secara **live** tanpa refresh halaman.

Fitur utama:

- 🔐 Login Admin (JWT Authentication)
- 🏷 Ubah status ruangan (**Realtime via WebSocket**)
- ➕ Tambah akun admin
- ✏️ Ubah nama & password admin
- ❌ Hapus akun sendiri (Self-delete)
- 📜 Riwayat login admin
- 🎨 Tampilan modern (Glassmorphism + Gradient)

**Teknologi Utama:**
- **Frontend** → Vite + HTML + JavaScript + Bootstrap 5  
- **Backend** → Golang (REST API + WebSocket)  
- **Database** → Supabase PostgreSQL  
- **Deploy** → Vercel (Frontend) + Render (Backend)

---

## 🚀 Cara Menjalankan Aplikasi (Local)

### 1️⃣ Clone Repository
git clone https://github.com/Nathanaelcpt/realtime-room-monitoring.git
cd realtime-room-monitoring

🛠 Backend (Golang)
### 2️⃣ Buat file .env pada folder backend

Isi sebagai berikut:

DATABASE_URL=postgres://username:password@host:port/dbname
JWT_SECRET=your-secret-key

### 3️⃣ Jalankan Backend
cd backend
go run main.go


Backend berjalan di:
➡️ http://localhost:8080

🎨 Frontend (Vite)
### 4️⃣ Masuk folder frontend
cd frontend

### 5️⃣ Install dependencies
npm install

### 6️⃣ Jalankan dev server
npm run dev


Frontend dapat diakses di:
➡️ http://localhost:5173

### 7️⃣ Build untuk produksi
npm run build


Hasil build berada di:
➡️ frontend/dist/

### 🔄 Mekanisme Realtime (WebSocket)

Admin mengubah status ruangan

Backend mengirim broadcast ke semua client yang terkoneksi

Pengguna langsung melihat perubahan tanpa refresh halaman

Animasi ditempatkan untuk memperhalus perubahan tampilan

Contoh Realtime Update:

Lab Komputer A → Digunakan
Langsung muncul di frontend user dalam < 1 detik

### 🖼 Cuplikan Tampilan
➡️ /screenshots/

### 📂 Struktur Folder (Ringkas)
realtime-room-monitoring/
│
├── backend/
│   ├── main.go
│   ├── database/
│   ├── handlers/
│   ├── middleware/
│   └── websocket/
│
├── frontend/
│   ├── index.html
│   ├── src/
│   └── dist/
│
└── README.md

### 📄 Keterangan

Project ini dibuat untuk memenuhi tugas mata kuliah:
Pemrograman Jaringan – Universitas Katolik Darma Cendika, 2025