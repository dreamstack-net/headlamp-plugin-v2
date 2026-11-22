import { vi } from 'vitest';

const mocks = vi.hoisted(() => ({ listCustomObjectConfigMaps: vi.fn() }));
vi.mock('../custom-objects/api-queries', () => ({
  listCustomObjectConfigMaps: mocks.listCustomObjectConfigMaps,
}));
vi.mock('../rego', () => ({
  defaultFrameworkNames: ['cis-v1.10.0'],
  useRegoData: () => ({ frameworks: [] }),
}));

import { chooseFrameworks, customFrameworkNames, shownByDefault } from './FrameworkSettings';

describe('chooseFrameworks', () => {
  const names = ['Acme Security Baseline v1', 'Acme Security Baseline v2'];

  it('keeps the framework the page opens with while it is chosen, or all controls', () => {
    expect(chooseFrameworks(names, names[1])).toEqual({
      activeFrameworks: names,
      framework: names[1],
    });
    expect(chooseFrameworks(names, '')).toEqual({ activeFrameworks: names, framework: '' });
    expect(chooseFrameworks(names, undefined)).toEqual({ activeFrameworks: names, framework: '' });
  });

  it('opens with the first chosen framework when its framework is no longer chosen', () => {
    expect(chooseFrameworks(names, 'NSA')).toEqual({
      activeFrameworks: names,
      framework: names[0],
    });
    expect(chooseFrameworks([], 'NSA')).toEqual({ activeFrameworks: [], framework: '' });
  });
});

describe('customFrameworkNames', () => {
  it('names the clusters of each custom framework and where it is a default', async () => {
    mocks.listCustomObjectConfigMaps.mockImplementation(async (_type: string, cluster: string) => {
      if (cluster === 'stopped') throw new Error('connection refused');
      return [
        {
          metadata: {
            labels: cluster === 'prd' ? { 'kubescape.io/default-framework': 'true' } : {},
          },
          data: { name: 'Acme v1' },
        },
        { metadata: {}, data: {} },
        ...(cluster === 'prd' ? [{ metadata: {}, data: { name: 'Prd only' } }] : []),
      ];
    });

    const found = await customFrameworkNames(['tst', 'stopped', 'prd']);

    // a cluster that cannot be read adds none
    expect([...found]).toEqual([
      ['Acme v1', { clusters: ['tst', 'prd'], defaultIn: ['prd'] }],
      ['Prd only', { clusters: ['prd'], defaultIn: [] }],
    ]);
    expect(shownByDefault(found)).toEqual(['Acme v1']);
    // without defaults in the clusters, Kubescape's
    expect(shownByDefault(new Map([['Prd only', { clusters: ['prd'], defaultIn: [] }]]))).toEqual([
      'cis-v1.10.0',
    ]);
  });
});
