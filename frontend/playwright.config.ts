import { defineConfig } from '@playwright/test'

// Deliberately not run by `npm test` or CI -- see e2e/smoke.spec.ts's
// module docstring for why (needs a live Postgres-backed API and a built
// frontend running simultaneously). Run manually: `npx playwright test`
// with BASE_URL pointed at a `vite preview` server and the API reachable
// with matching CORS/origins.
export default defineConfig({
  testDir: './e2e',
  use: {
    baseURL: process.env.BASE_URL || 'http://localhost:4173',
    screenshot: 'only-on-failure',
  },
  reporter: 'list',
})
