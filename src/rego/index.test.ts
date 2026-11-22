import { vi } from 'vitest';

vi.mock('./RegoDataProvider', () => ({ RegoDataProvider: () => null, useRegoData: vi.fn() }));

import { activeFrameworkNames, defaultFrameworkNames, FrameWork } from './index';

const framework = (name: string, isDefault?: boolean) =>
  ({ name, controls: [], ...(isDefault ? { isDefault } : {}) } as FrameWork);

it('shows the chosen frameworks, else the defaults of the cluster, else those of Kubescape', () => {
  const custom = [
    framework('Acme Security Baseline v1', true),
    framework('Acme Security Baseline v2', true),
    framework('Team draft'),
  ];

  expect(activeFrameworkNames(['NSA'], custom)).toEqual(['NSA']);
  expect(activeFrameworkNames([], custom)).toEqual([
    'Acme Security Baseline v1',
    'Acme Security Baseline v2',
  ]);
  expect(activeFrameworkNames(undefined, [framework('Team draft')])).toEqual(defaultFrameworkNames);
  expect(activeFrameworkNames(null)).toEqual(['cis-v1.10.0', 'MITRE', 'NSA']);
});
