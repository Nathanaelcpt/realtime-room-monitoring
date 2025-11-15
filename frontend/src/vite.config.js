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

  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        login: resolve(__dirname, 'login.html'),
        admin: resolve(__dirname, 'admin.html'),
        register: resolve(__dirname, 'register.html'),
        settings: resolve(__dirname, 'settings.html'),
      },
    },
  },
});
