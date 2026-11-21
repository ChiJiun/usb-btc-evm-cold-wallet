import type { SnapConfig } from '@metamask/snaps-cli';

const config: SnapConfig = {
  input: 'src/index.ts',
  output: { path: 'dist' },
  server: { port: 8082 },
};

export default config;
