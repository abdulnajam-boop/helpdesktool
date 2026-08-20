import { expect, test } from '@playwright/test'

/**
 * Real browser E2E smoke test — release-candidate validation, run manually
 * against a live backend + `vite preview` build (not wired into CI: needs a
 * real Postgres-backed API and a built frontend running simultaneously, and
 * this repo's CI doesn't stand up that combination anywhere else). See
 * docs/RELEASE_READINESS.md for the exact commands used to run this for
 * real against a genuine Chromium browser as part of v0.1.0-rc1 validation.
 *
 * Exercises the actual DOM in a real browser: dev login, navigation across
 * every primary page, and the Reports page specifically (added this
 * session, never previously verified in a real browser — see
 * docs/IMPLEMENTATION_PLAN.md's reporting-layer cross-cutting entry).
 */

test('dev login, primary navigation, and the Reports page all render with no console errors', async ({
  page,
}) => {
  const consoleErrors: string[] = []
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text())
  })
  page.on('pageerror', (err) => consoleErrors.push(err.message))

  await page.goto('/')
  await expect(page.locator('.dev-note')).toContainText('Development login')

  const ownerButton = page.locator('.login-users button').first()
  await expect(ownerButton).toBeVisible()
  await ownerButton.click()

  await expect(page.locator('.shell')).toBeVisible({ timeout: 10000 })
  await expect(page.locator('.title h1')).toContainText('Operations overview')

  const pages: [string, string][] = [
    ['/devices', 'Devices'],
    ['/tickets', 'Tickets'],
    ['/incidents', 'Incidents'],
    ['/actions', 'Actions'],
    ['/approvals', 'Approvals'],
    ['/skills', 'Skills'],
    ['/reports', 'Reports'],
    ['/audit', 'Audit'],
    ['/integrations', 'Integrations'],
    ['/settings', 'Settings'],
  ]

  for (const [href, navText] of pages) {
    await page.locator(`nav a[href="${href}"]`).click()
    await expect(page).toHaveURL(new RegExp(`${href}$`))
    await expect(page.locator('.state.error')).toHaveCount(0)
  }

  // Reports page specifically: real data from the seeded demo tenant should
  // render as actual numbers, and the period selector should trigger a
  // real re-fetch without erroring.
  await page.locator('nav a[href="/reports"]').click()
  await expect(page.locator('.cards .metric').first()).toBeVisible()
  await expect(page.locator('.report-stats').first()).toBeVisible()
  await page.locator('select').selectOption('30')
  await expect(page.locator('.state.error')).toHaveCount(0)

  await page.locator('.identity button').click()
  await expect(page.locator('.dev-note')).toBeVisible()

  expect(consoleErrors, `Browser console errors: ${consoleErrors.join('\n')}`).toEqual([])
})
