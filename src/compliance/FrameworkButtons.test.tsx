import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  config: { activeFrameworks: ['NSA', 'Acme Security Baseline v1'] } as {
    activeFrameworks: string[];
    framework?: string;
  },
  update: vi.fn(),
}));
vi.mock('../common/config-store', () => ({
  kubescapeConfigStore: { get: () => mocks.config, update: mocks.update },
}));
vi.mock('./Compliance', () => ({ configurationScanContext: { workloadScans: [] } }));
vi.mock('./workload-scanning', () => ({ frameworkComplianceScore: () => 80 }));
vi.mock('../rego', () => ({
  activeFrameworkNames: (names: string[]) => names,
  useRegoData: () => ({ frameworks: [{ name: 'NSA', controls: [] }] }),
}));

import { FrameworkButtons } from './FrameworkButtons';

afterEach(cleanup);

it('names the chosen frameworks this cluster does not have, once its custom ones were read', () => {
  const { rerender } = render(
    <FrameworkButtons frameworkName="" customFrameworks={[]} customFrameworksRead={false} />
  );
  // while the custom frameworks are read, nothing is missing yet
  expect(screen.queryByText(/Not in this cluster/)).toBeNull();

  rerender(<FrameworkButtons frameworkName="" customFrameworks={[]} customFrameworksRead />);
  expect(screen.getByText('Not in this cluster: Acme Security Baseline v1')).toBeTruthy();
  expect(screen.getByLabelText(/NSA/)).toBeTruthy();

  // a cluster that has it
  rerender(
    <FrameworkButtons
      frameworkName=""
      customFrameworks={[{ name: 'Acme Security Baseline v1', controls: [] } as any]}
      customFrameworksRead
    />
  );
  expect(screen.queryByText(/Not in this cluster/)).toBeNull();
  expect(screen.getByLabelText(/Acme Security Baseline v1/)).toBeTruthy();
});

it('shows all controls again when the framework the page shows is unchecked', () => {
  mocks.update.mockReset();
  mocks.config = { activeFrameworks: ['NSA', 'Acme Security Baseline v1'], framework: 'NSA' };
  render(<FrameworkButtons frameworkName="NSA" customFrameworks={[]} customFrameworksRead />);

  // unchecks NSA in the Frameworks menu: its radio button goes, so the page leaves it too
  fireEvent.mouseDown(screen.getByRole('combobox'));
  fireEvent.click(within(screen.getByRole('listbox')).getByText('NSA'));
  expect(mocks.update).toHaveBeenLastCalledWith({
    activeFrameworks: ['Acme Security Baseline v1'],
    framework: '',
  });
});

it('keeps the framework the page shows when another one is unchecked', () => {
  mocks.update.mockReset();
  mocks.config = { activeFrameworks: ['NSA', 'MITRE'], framework: 'NSA' };
  render(
    <FrameworkButtons
      frameworkName="NSA"
      customFrameworks={[{ name: 'MITRE', controls: [] } as any]}
      customFrameworksRead
    />
  );

  fireEvent.mouseDown(screen.getByRole('combobox'));
  fireEvent.click(within(screen.getByRole('listbox')).getByText('MITRE'));
  expect(mocks.update).toHaveBeenLastCalledWith({ activeFrameworks: ['NSA'] });
});
