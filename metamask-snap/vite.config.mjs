import { defineConfig } from 'vite';
export default defineConfig({ root: 'companion', base: './', build: { outDir: '../dist-companion', emptyOutDir: true }, server: { host: '127.0.0.1', port: 8000, strictPort: true } });
