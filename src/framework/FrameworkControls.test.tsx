import { cleanup, render, screen } from '@testing-library/react';
import { vi } from 'vitest';
import { FrameworkControls } from './FrameworkControls';

const mocks = vi.hoisted(() => ({
  // the columns the table got
  columns: [] as any[],
}));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  NameValueTable: () => null,
  SectionBox: ({ children }: any) => <section>{children}</section>,
  Table: ({ columns }: any) => {
    mocks.columns = columns;
    return null;
  },
}));
vi.mock('../common/url', () => ({ getURLSegments: () => ['NSA'] }));
vi.mock('../compliance/Compliance', () => ({
  complianceSeverity: (baseScore: number) => (baseScore >= 7 ? 'High' : 'Low'),
}));
vi.mock('../rego', () => ({
  useRegoData: () => ({ frameworks: [{ name: 'NSA', controls: [] }] }),
}));

afterEach(cleanup);

it('gives the severity of a control its score as the value, which sorts, and draws the label', () => {
  render(<FrameworkControls />);
  const severity = mocks.columns.find(column => column.header === 'Severity');
  const control = { controlID: 'C-0016', baseScore: 8 };

  // a label as the value would sort as an object
  expect(severity.accessorFn(control)).toBe(8);
  render(<>{severity.Cell({ row: { original: control } })}</>);
  expect(screen.getByText('High')).toBeTruthy();
});
