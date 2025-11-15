export default {
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
};
