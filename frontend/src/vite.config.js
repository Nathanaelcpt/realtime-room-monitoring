import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  server: {
    proxy: {
      '/rooms': 'http://localhost:8080',
      '/login': 'http://localhost:8080',
      '/update': 'http://localhost:8080',
      '/ws': {
        target: 'ws://localhost:8080',
        ws: true,
      },
    },
  },

  // ⬇️ Ini bagian penting supaya login.html dan halaman lain ikut kebuild
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        login: resolve(__dirname, 'login.html'),
        dashboard: resolve(__dirname, 'dashboard.html'),
        // Tambah lagi kalau punya file lain:
        // register: resolve(__dirname, 'register.html'),
      }
    }
  }
});
