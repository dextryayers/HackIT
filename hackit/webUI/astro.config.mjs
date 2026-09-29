import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  integrations: [react()],
  vite: {
    plugins: [tailwindcss()],
  },
  server: {
    // Port 4321 matches ASTRO_DEV_URL in python/main.py so the backend can
    // proxy to the dev server. Never use 8080 here: that is the backend port.
    port: 4321,
    host: '127.0.0.1'
  }
});
