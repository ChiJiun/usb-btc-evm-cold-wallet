import {defineConfig} from 'vite';
import {nodePolyfills} from 'vite-plugin-node-polyfills';
export default defineConfig({base:'./',plugins:[nodePolyfills({include:['buffer','crypto','events','stream','util','process','assert']})],server:{host:'127.0.0.1',port:8011,strictPort:true},build:{outDir:'dist',emptyOutDir:true}});
