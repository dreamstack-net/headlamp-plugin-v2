import { vi } from 'vitest';

const mocks = vi.hoisted(() => ({ listCustomObjectConfigMaps: vi.fn() }));
vi.mock('../custom-objects/api-queries', () => ({
  listCustomObjectConfigMaps: mocks.listCustomObjectConfigMaps,
}));

import type { Control } from '../rego';
import { fetchCustomFrameworks } from './useCustomFrameworks';

const control = (controlID: string) => ({ controlID, name: controlID } as Control);

it('reads the custom frameworks of a cluster with their controls', async () => {
  mocks.listCustomObjectConfigMaps.mockResolvedValue([
    {
      metadata: { name: 'acme-security-baseline-v1', namespace: 'kubescape' },
      data: {
        name: 'Acme Security Baseline v1',
        description: 'Our baseline',
        controlsIDs: '["C-0012","C-0035","C-9999"]',
      },
    },
    // a ConfigMap without a name is no framework
    { metadata: { name: 'broken', namespace: 'kubescape' }, data: {} },
  ]);

  const frameworks = await fetchCustomFrameworks(
    [control('C-0012'), control('C-0035'), control('C-0057')],
    'prd'
  );

  expect(mocks.listCustomObjectConfigMaps).toHaveBeenCalledWith('framework', 'prd');
  expect(frameworks).toHaveLength(1);
  expect(frameworks[0].name).toBe('Acme Security Baseline v1');
  // the controls the plugin knows
  expect(frameworks[0].controls.map(found => found.controlID)).toEqual(['C-0012', 'C-0035']);
  expect(frameworks[0].configmapNamespace).toBe('kubescape');
});
