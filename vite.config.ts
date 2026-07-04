import { defineConfig } from 'vite';

export default defineConfig(({ mode }) => ({
  build: {
    outDir: 'src/main/webapp/js',
    emptyOutDir: true,
    sourcemap: mode === 'development' ? 'inline' : true,
    minify: mode !== 'development',
    rollupOptions: {
      input: 'src/main/frontend/index.ts',
      output: {
        // fixed name - referenced from AzureAdMatrixAuthorizationStrategy/config.jelly
        entryFileNames: 'azure-ad-bundle.js',
        inlineDynamicImports: true,
      },
    },
  },
}));
