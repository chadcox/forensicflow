import { test } from '@playwright/test';
import { gotoApp, installApiMocks, loginViaUi } from './helpers';

// Captures README screenshots from the mocked UI (deterministic, no Docker/evidence needed).
// Run: npm run screenshots   ->   ../../docs/screenshots/*.png
// ponytail: reuses e2e mocks instead of a live stack; if README needs real data, point at a running web service.

const OUT = '../../docs/screenshots';
const workspace = '/cases/22222222-2222-2222-2222-222222222222';

test.use({ viewport: { width: 1440, height: 900 } });

test('capture readme screenshots', async ({ page }) => {
  // animations: 'disabled' freezes the `animate-in` fade so shots aren't dimmed/blank.
  const shot = (name: string) =>
    page.screenshot({ path: `${OUT}/${name}.png`, fullPage: true, animations: 'disabled' });

  await installApiMocks(page, { authedInitially: false, allowCaseCreate: true });
  await loginViaUi(page);

  // Cases list
  await page.getByText('WKS-042 Investigation').waitFor();
  await shot('02-cases');

  // Investigation workspace — one shot per primary view
  await gotoApp(page, workspace);
  await page.getByRole('heading', { name: 'WKS-042 Investigation' }).waitFor();
  await shot('03-timeline');

  for (const [view, heading] of [
    ['Entities', 'Entities'],
    ['Disk', 'Disk'],
    ['MFT', 'MFT Records'],
    ['Browser', 'Browser'],
  ] as const) {
    await page.getByRole('button', { name: view, exact: true }).click();
    await page.getByRole('heading', { name: heading }).waitFor();
    await shot(`04-${view.toLowerCase()}`);
  }
});
