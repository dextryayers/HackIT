import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  integrations: [tailwind()],
  server: {
    port: 4322,
    host: '127.0.0.1'
  },
  outDir: 'dist',
  cacheDir: '/tmp/astro-cache-hackit'
});
