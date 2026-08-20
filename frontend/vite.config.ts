import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
export default defineConfig({
  plugins: [react()],
  server: { port: 3000 },
  build: { outDir: 'dist' },
  // e2e/** holds Playwright specs (real-browser tests, run manually via
  // `npx playwright test` -- see e2e/smoke.spec.ts's module docstring),
  // not vitest ones; vitest's default include pattern would otherwise try
  // to collect them and fail on Playwright's async test.describe usage.
  test: {
    environment: 'jsdom',
    pool: 'threads',
    exclude: ['**/node_modules/**', '**/e2e/**'],
  },
})
