import { vi } from 'vitest';
import { customFrameworkOf, parseControlIDs } from './customFrameworks';

const controls = [{ controlID: 'C-0016' }, { controlID: 'C-0017' }] as any[];

it('reads the control IDs of a custom framework', () => {
  expect(parseControlIDs('["C-0016","C-0017"]')).toEqual(['C-0016', 'C-0017']);
  expect(parseControlIDs(undefined)).toEqual([]);
});

it('gives no controls for a ConfigMap edited by hand into something else', () => {
  const error = vi.spyOn(console, 'error').mockImplementation(() => {});
  expect(parseControlIDs('not json', 'framework-x')).toEqual([]);
  expect(parseControlIDs('{"C-0016":true}')).toEqual([]);
  expect(parseControlIDs('null')).toEqual([]);
  // the IDs that are text
  expect(parseControlIDs('["C-0016", 17, null]')).toEqual(['C-0016']);
  expect(error).toHaveBeenCalledWith('Failed to parse controlsIDs for framework', 'framework-x');
  error.mockRestore();
});

it('makes a framework of a ConfigMap with a name, keeping where the ConfigMap is', () => {
  expect(
    customFrameworkOf(
      {
        metadata: { name: 'team-framework-abc', namespace: 'kubescape' },
        data: { name: 'Team', description: 'Ours', controlsIDs: '["C-0017","C-0099"]' },
      },
      controls
    )
  ).toEqual({
    name: 'Team',
    description: 'Ours',
    controls: [{ controlID: 'C-0017' }],
    configmapManifestName: 'team-framework-abc',
    configmapNamespace: 'kubescape',
  });
  expect(customFrameworkOf({ metadata: { name: 'x' }, data: {} }, controls)).toBeUndefined();
  expect(customFrameworkOf({ metadata: { name: 'x' } }, controls)).toBeUndefined();
});

it('marks a framework its cluster labels as a default', () => {
  const configMap = (labels?: Record<string, string>) => ({
    metadata: { name: 'acme-security-baseline-v1', namespace: 'kubescape', labels },
    data: { name: 'Acme Security Baseline v1', controlsIDs: '["C-0016"]' },
  });

  expect(
    customFrameworkOf(configMap({ 'kubescape.io/default-framework': 'true' }), controls)?.isDefault
  ).toBe(true);
  // any other value, or no label, is no default
  expect(
    customFrameworkOf(configMap({ 'kubescape.io/default-framework': 'false' }), controls)
  ).not.toHaveProperty('isDefault');
  expect(customFrameworkOf(configMap(), controls)).not.toHaveProperty('isDefault');
});
