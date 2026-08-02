import { defineConfig, devices } from '@playwright/test';

// 4266: unused by any sibling lab (the fleet holds 4208…4390 elsewhere). Never
// 4173 — with 100+ labs checked out side by side, the Vite default means
// `reuseExistingServer` can silently scan a different lab's preview.
const PORT = 4266;
const BASE = '/crypto-lab-matsui-line/';

export default defineConfig({
  testDir: './e2e',
  // Visual baselines are per-platform, so a macOS snapshot fails on the Linux
  // CI runner for reasons unrelated to the change. Visual regression is opt-in
  // via `npm run test:visual`; a11y and behaviour are what gate the deploy.
  testIgnore: process.env.VISUAL ? [] : ['**/visual.spec.ts'],
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  // The sweep drives every exhibit — including the key-recovery attack and the
  // measured success-rate curve, which are real computations over thousands of
  // known plaintexts — and scans a dozen states per theme.
  timeout: 240_000,
  workers: process.env.CI ? 1 : undefined,
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    // Build before serving. `preview` only serves whatever is already in
    // dist/; without the build in front, a failing build leaves the previous
    // good bundle on disk and the suite passes green against code that no
    // longer compiles — silently invalidating mutation checks.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
