// Real-browser E2E smoke test, run inside the official Playwright Docker
// image (mcr.microsoft.com/playwright) against the production frontend and
// API container images -- not a dev server, not jsdom. See run.sh for the
// full orchestration (network, containers, seed data) this script expects
// to already be running before it starts.
//
// This exists because `frontend/`'s own test suite (Vitest + jsdom, see
// auth/oidc.test.ts) can prove component logic but can never catch a bug
// that only exists in the browser's actual render/effect loop -- which is
// exactly how this script caught a real one on first run: Reports.tsx
// computed `new Date()` directly in the render body, so its useApi() fetch
// path changed by a few milliseconds on every re-render, causing an
// infinite fetch loop that hammered the API and left the page stuck on
// "Loading..." forever. Nothing in the SQLite-backed pytest suite or the
// Vitest suite could have caught that -- both mock or bypass the real
// browser fetch/render cycle this script actually exercises. Fixed by
// memoizing the computed path with useMemo(..., [days]); this script is
// what proved the fix.
import { chromium } from 'playwright'
import fs from 'fs'

const BASE = process.env.E2E_BASE_URL || 'http://helpdesk-e2e-frontend'
const outDir = process.env.E2E_OUT_DIR || '/work'
const shotDir = `${outDir}/screenshots`
fs.mkdirSync(shotDir, { recursive: true })

const results = []
function record(name, ok, detail) {
  results.push({ name, ok, detail: detail || '' })
  console.log(`${ok ? 'PASS' : 'FAIL'}: ${name}${detail ? ' -- ' + detail : ''}`)
}

const browser = await chromium.launch()
const context = await browser.newContext()
const page = await context.newPage()
const consoleErrors = []
page.on('console', (msg) => {
  if (msg.type() === 'error') consoleErrors.push(msg.text())
})
page.on('pageerror', (err) => consoleErrors.push(String(err)))

try {
  // 1. Login page loads (dev login, since no OIDC is configured for this run)
  await page.goto(BASE, { waitUntil: 'networkidle', timeout: 15000 })
  await page.screenshot({ path: `${shotDir}/01-login.png` })
  const loginVisible = await page
    .locator('.login')
    .isVisible()
    .catch(() => false)
  record('login page renders', loginVisible)

  // 2. Dev login users are listed and clickable
  const userButtons = page.locator('.login-users button')
  const count = await userButtons.count()
  record('dev login lists at least one user', count > 0, `found ${count}`)
  if (count > 0) {
    await userButtons.first().click()
    await page.waitForURL('**/', { timeout: 10000 }).catch(() => {})
    await page.waitForSelector('.shell', { timeout: 10000 })
    await page.screenshot({ path: `${shotDir}/02-dashboard.png` })
    record('logged in and dashboard shell rendered', true)
  }

  // 3. Dashboard shows real counts (not stuck loading/error)
  await page.waitForSelector('.cards .metric', { timeout: 10000 })
  const metricCount = await page.locator('.cards .metric').count()
  record('dashboard renders metric cards', metricCount > 0, `found ${metricCount}`)
  const dashboardError = await page.locator('.state.error').count()
  record('no error state visible on dashboard', dashboardError === 0)

  // 4. Incidents page (should show any incident seeded before this ran)
  await page.click('nav a[href="/incidents"]')
  await page.waitForURL('**/incidents')
  await page.waitForLoadState('networkidle')
  await page.screenshot({ path: `${shotDir}/03-incidents.png` })
  record('incidents page loads without error', (await page.locator('.state.error').count()) === 0)

  // 5. Reports page -- the specific page this script exists to catch
  // render-loop bugs in; see the module comment above.
  await page.click('nav a[href="/reports"]')
  await page.waitForURL('**/reports')
  await page.waitForLoadState('networkidle', { timeout: 15000 })
  await page.waitForSelector('.report-stats', { timeout: 10000 })
  await page.screenshot({ path: `${shotDir}/04-reports.png` })
  const reportStatsBlocks = await page.locator('.report-stats').count()
  record('reports page renders report-stats panels', reportStatsBlocks > 0, `found ${reportStatsBlocks}`)

  // Change the period selector and confirm the page re-fetches once and
  // settles -- the exact behavior the infinite-loop bug broke.
  await page.selectOption('.title select', '30')
  await page.waitForLoadState('networkidle', { timeout: 15000 })
  record(
    'reports page period selector re-fetches and settles without error',
    (await page.locator('.state.error').count()) === 0,
  )

  // 6. Devices page
  await page.click('nav a[href="/devices"]')
  await page.waitForURL('**/devices')
  await page.waitForLoadState('networkidle')
  await page.screenshot({ path: `${shotDir}/05-devices.png` })
  record('devices page loads without error', (await page.locator('.state.error').count()) === 0)

  // 7. Skills page
  await page.click('nav a[href="/skills"]')
  await page.waitForURL('**/skills')
  await page.waitForLoadState('networkidle')
  record('skills page loads without error', (await page.locator('.state.error').count()) === 0)

  // 8. Sign out returns to login
  await page.click('.identity button')
  await page.waitForSelector('.login', { timeout: 10000 })
  record('sign out returns to login page', true)

  record(
    'no uncaught browser console errors during the whole run',
    consoleErrors.length === 0,
    consoleErrors.join(' | '),
  )
} catch (err) {
  record('unhandled exception during E2E run', false, String(err))
  await page.screenshot({ path: `${shotDir}/error.png` }).catch(() => {})
} finally {
  await browser.close()
}

fs.writeFileSync(`${outDir}/results.json`, JSON.stringify(results, null, 2))
const failed = results.filter((r) => !r.ok)
console.log(`\n${results.length - failed.length}/${results.length} checks passed`)
process.exit(failed.length > 0 ? 1 : 0)
