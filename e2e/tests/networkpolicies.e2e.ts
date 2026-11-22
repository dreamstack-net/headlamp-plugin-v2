import { expect, searchTable, test } from './fixtures';
import { kubescapePath } from './helpers';

test.describe('Network Policies', () => {
  test('lists the generated network policies of the workloads', async ({ page }) => {
    await page.goto(kubescapePath('networkpolicies'));
    const main = page.getByRole('main');
    await expect(
      main.getByRole('heading', { name: 'Generated Network Policies', level: 1 })
    ).toBeVisible();
    const panel = main.getByRole('tabpanel', { name: 'Policies' });
    await searchTable(panel, 'shop');
    for (const [name, kind] of [
      ['web', 'Deployment'],
      ['api', 'Deployment'],
      ['cache', 'StatefulSet'],
    ]) {
      const row = panel
        .getByRole('row')
        .filter({ has: page.getByRole('link', { name, exact: true }) });
      await expect(row).toBeVisible();
      await expect(row).toContainText(kind);
      await expect(row).toContainText('shop');
    }
    // the api deployment calls the web service: one egress of api, one ingress of web
    const api = panel
      .getByRole('row')
      .filter({ has: page.getByRole('link', { name: 'api', exact: true }) });
    await expect(api.getByRole('cell').nth(4)).not.toHaveText('0');
    await main.getByRole('tab', { name: 'Known Servers' }).click();
    await expect(main.getByRole('tabpanel', { name: 'Known Servers' })).toBeVisible();
  });

  test('draws the diagram of the traffic of a workload', async ({ page }) => {
    await page.goto(kubescapePath('networkpolicies'));
    const panel = page.getByRole('tabpanel', { name: 'Policies' });
    await searchTable(panel, 'shop');
    await panel.getByRole('link', { name: 'api', exact: true }).click();

    await expect(page).toHaveURL(
      new RegExp(`${kubescapePath('networkpolicies/shop/deployment-api')}$`)
    );
    const main = page.getByRole('main');
    await expect(
      main.getByRole('heading', { name: 'Generated Network Policy - api' })
    ).toBeVisible();
    const diagram = main.getByRole('tabpanel', { name: 'Diagram' });
    // the workload, the web pods it calls and DNS, joined by edges
    const nodes = diagram.locator('.react-flow__node');
    await expect(nodes.filter({ hasText: 'Deployment' }).filter({ hasText: 'api' })).toBeVisible();
    await expect(nodes.filter({ hasText: 'app=web' })).toBeVisible();
    await expect(nodes.filter({ hasText: 'k8s-app=kube-dns' })).toBeVisible();
    await expect(diagram.locator('.react-flow__edge').first()).toBeAttached();
    expect(await diagram.locator('.react-flow__edge').count()).toBeGreaterThanOrEqual(2);
    // React Flow measured the nodes before the layout, so they do not overlap at the origin
    const boxes = await nodes.evaluateAll(elements =>
      elements
        .map(element => element.getBoundingClientRect())
        .map(({ x, y, width, height }) => ({ x, y, width, height }))
    );
    expect(boxes.every(box => box.width > 0 && box.height > 0)).toBe(true);
    expect(new Set(boxes.map(box => `${Math.round(box.x)},${Math.round(box.y)}`)).size).toBe(
      boxes.length
    );

    // the policy as YAML, and the policies of the namespace compared with the traffic
    await main.getByRole('tab', { name: 'NetworkPolicy' }).click();
    await expect(main.getByRole('tabpanel', { name: 'NetworkPolicy' })).toContainText(
      'kind: NetworkPolicy'
    );
    await main.getByRole('tab', { name: 'Current policies' }).click();
    await expect(main.getByRole('tabpanel', { name: 'Current policies' })).toBeVisible();
  });
});
