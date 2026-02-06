import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  // Bundle @ai-agent-auth/core into the client package
  noExternal: ['@ai-agent-auth/core'],
});
