import { spawnSync } from 'node:child_process';
import { expect, test } from './fixtures';
import { deleteIfExists, kubeContext, kubectl, kubectlJson, kubescapePath } from './helpers';

// a policy of the Kubescape library without parameters: containers need a read-only filesystem
const policy = 'kubescape-c-0017-deny-resources-with-mutable-container-filesystem';
const binding = `${policy}-binding`;
// the namespace the installed binding is limited to
const namespace = 'shop';

function removePolicy() {
  deleteIfExists('validatingadmissionpolicybindings.admissionregistration.k8s.io', binding);
  deleteIfExists('validatingadmissionpolicies.admissionregistration.k8s.io', policy);
}

test.describe('Policy Playground', () => {
  test('evaluates a sample policy against a sample resource', async ({ page }) => {
    await page.goto(kubescapePath('vap'));
    const main = page.getByRole('main');
    await main.getByRole('combobox', { name: 'Choose Sample Policy' }).click();
    await page.getByRole('option', { name: policy, exact: true }).click();
    await expect(main.getByRole('combobox', { name: 'Choose Sample Policy' })).toHaveText(policy);
    await expect(main.getByRole('button', { name: 'Install in cluster' })).toBeEnabled();

    await main.getByRole('combobox', { name: 'Choose Test Resource' }).click();
    await page.getByRole('option', { name: 'deployment.yaml', exact: true }).click();

    // the WASM evaluator: the sample deployment has a mutable filesystem
    const validations = main
      .getByRole('table')
      .filter({ hasText: 'Expression' })
      .filter({ hasText: 'readOnlyRootFilesystem' });
    await expect(validations.first()).toBeVisible();
    await expect(validations.first()).toContainText(/false/i);
    await expect(validations.first()).toContainText('mutable filesystem not allowed');
  });

  test('evaluates a policy against an object of the cluster', async ({ page }) => {
    await page.goto(kubescapePath('vap'));
    const main = page.getByRole('main');
    await main.getByRole('combobox', { name: 'Choose Sample Policy' }).click();
    await page.getByRole('option', { name: policy, exact: true }).click();
    await main
      .getByRole('group', { name: 'Test resource source' })
      .getByRole('button', { name: 'From cluster' })
      .click();
    const object = main.getByRole('combobox', { name: 'Namespace/name' });
    await object.click();
    await object.fill('shop/web');
    await page.getByRole('option', { name: 'shop/web', exact: true }).click();
    const validations = main
      .getByRole('table')
      .filter({ hasText: 'Expression' })
      .filter({ hasText: 'readOnlyRootFilesystem' });
    await expect(validations.first()).toContainText(/false/i);
  });

  test('installs a policy that only warns, and the API server warns with it', async ({ page }) => {
    removePolicy();
    try {
      await page.goto(kubescapePath('vap'));
      const main = page.getByRole('main');
      await main.getByRole('combobox', { name: 'Choose Sample Policy' }).click();
      await page.getByRole('option', { name: policy, exact: true }).click();
      await main.getByRole('button', { name: 'Install in cluster' }).click();

      const dialog = page.getByRole('dialog', { name: 'Install policy in cluster' });
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText(`${policy}-binding`);
      // Deny is not offered
      await expect(dialog.getByRole('checkbox', { name: 'Deny' })).toHaveCount(0);
      await dialog.getByRole('checkbox', { name: 'Warn' }).check();
      await dialog.getByRole('checkbox', { name: 'Audit' }).uncheck();
      await dialog.getByRole('textbox', { name: 'Namespace' }).fill(namespace);
      await dialog.getByRole('button', { name: 'Install' }).click();
      await expect(
        dialog
          .getByRole('alert')
          .filter({ hasText: /install/i })
          .last()
      ).toBeVisible();
      await expect(dialog.getByRole('alert').filter({ hasText: /unable|fail|error/i })).toHaveCount(
        0
      );

      // the policy and its binding as the API server has them
      const installed = kubectlJson(['get', 'validatingadmissionpolicy', policy]);
      expect(installed.spec.failurePolicy).toBe('Ignore');
      const installedBinding = kubectlJson(['get', 'validatingadmissionpolicybinding', binding]);
      expect(installedBinding.spec.policyName).toBe(policy);
      expect(installedBinding.spec.validationActions).toEqual(['Warn']);
      expect(JSON.stringify(installedBinding.spec.matchResources)).toContain(namespace);

      // a deployment with a mutable filesystem is admitted, with a warning
      await expect(async () => {
        const result = spawnSync(
          'kubectl',
          [
            '--context',
            kubeContext,
            'create',
            'deployment',
            'e2e-mutable',
            '-n',
            namespace,
            '--image=busybox:1.36.0',
            '--dry-run=server',
            '-o',
            'name',
          ],
          { encoding: 'utf8' }
        );
        expect(result.status, result.stderr).toBe(0);
        expect(result.stderr).toContain('mutable filesystem not allowed');
      }).toPass({ timeout: 60_000 });
      // and none in another namespace
      const other = spawnSync(
        'kubectl',
        [
          '--context',
          kubeContext,
          'create',
          'deployment',
          'e2e-mutable',
          '-n',
          'tools',
          '--image=busybox:1.36.0',
          '--dry-run=server',
          '-o',
          'name',
        ],
        { encoding: 'utf8' }
      );
      expect(other.status).toBe(0);
      expect(other.stderr).not.toContain('mutable filesystem not allowed');
    } finally {
      removePolicy();
    }
    expect(kubectl(['get', 'validatingadmissionpolicies', '-o', 'name'])).not.toContain(policy);
  });
});
