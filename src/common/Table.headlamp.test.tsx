// Renders Headlamp's real table, to check that it keeps the sorting the plugin gives it
import { lightTheme } from '@kinvolk/headlamp-plugin/lib/components/App/defaultAppThemes';
import { createMuiTheme } from '@kinvolk/headlamp-plugin/lib/lib/themes';
import {
  defaultTableRowsPerPageOptions,
  setAppSettings,
} from '@kinvolk/headlamp-plugin/lib/redux/configSlice';
import store from '@kinvolk/headlamp-plugin/lib/redux/stores/store';
import { ThemeProvider } from '@mui/material/styles';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { Provider } from 'react-redux';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';

const mocks = vi.hoisted(() => ({ saveToFile: vi.fn() }));
vi.mock('./filedialog', () => ({ saveToFile: mocks.saveToFile }));
import Table, { withColumnIds } from './Table';

const data = [
  { name: 'beta', score: 3 },
  { name: 'alpha', score: 1 },
  { name: 'gamma', score: 2 },
];
const columns = [
  // Headlamp names columns without an id by their index
  { id: 'name', header: 'Name', accessorKey: 'name' },
  { id: 'score', header: 'Score', accessorKey: 'score' },
];

function names() {
  return screen
    .getAllByRole('row')
    .slice(1)
    .map(row => within(row).getAllByRole('cell')[0].textContent);
}

function renderTable() {
  render(
    <Provider store={store}>
      <ThemeProvider theme={createMuiTheme(lightTheme)}>
        <MemoryRouter>
          <Table
            data={data}
            columns={columns}
            initialState={{ sorting: [{ id: 'name', desc: false }] }}
          />
        </MemoryRouter>
      </ThemeProvider>
    </Provider>
  );
}

beforeEach(() => window.sessionStorage.clear());
afterEach(cleanup);

it('shows the rows sorted as the user left them when the page is shown again', async () => {
  renderTable();
  expect(names()).toEqual(['alpha', 'beta', 'gamma']);

  // the user sorts by score
  fireEvent.click(screen.getByText('Score'));
  const sortedByScore = names();
  expect(sortedByScore).not.toEqual(['alpha', 'beta', 'gamma']);
  cleanup();

  // back on the page, the table is mounted anew
  renderTable();
  expect(names()).toEqual(sortedByScore);
});

it('keeps the sorting of each kind of table apart', () => {
  renderTable();
  fireEvent.click(screen.getByText('Score'));
  const sortedByScore = names();
  cleanup();

  // a table with other columns starts with its own initial sorting
  render(
    <Provider store={store}>
      <ThemeProvider theme={createMuiTheme(lightTheme)}>
        <MemoryRouter>
          <Table
            data={data}
            columns={[{ id: 'name', header: 'Workload', accessorKey: 'name' }]}
            initialState={{ sorting: [{ id: 'name', desc: true }] }}
          />
        </MemoryRouter>
      </ThemeProvider>
    </Provider>
  );
  expect(names()).toEqual(['gamma', 'beta', 'alpha']);
  cleanup();

  renderTable();
  expect(names()).toEqual(sortedByScore);
});

it('keeps the sorting on its column when a column appears before it', () => {
  // without ids, as most columns of the plugin: Headlamp names such a column by its index
  const table = (withCluster: boolean) => (
    <Provider store={store}>
      <ThemeProvider theme={createMuiTheme(lightTheme)}>
        <MemoryRouter>
          <Table
            data={data}
            sortingKey="scores"
            columns={[
              { header: 'Name', accessorKey: 'name' },
              ...(withCluster ? [{ header: 'Cluster', accessorFn: () => 'cluster-a' }] : []),
              { header: 'Score', accessorKey: 'score' },
            ]}
          />
        </MemoryRouter>
      </ThemeProvider>
    </Provider>
  );
  const view = render(table(false));
  // numbers are sorted largest first
  fireEvent.click(screen.getByText('Score'));
  expect(names()).toEqual(['beta', 'gamma', 'alpha']);

  // a second cluster is selected while the page is shown
  view.rerender(table(true));
  expect(names()).toEqual(['beta', 'gamma', 'alpha']);
  cleanup();

  // and back on the page
  render(table(true));
  expect(names()).toEqual(['beta', 'gamma', 'alpha']);
});

it('names a column by its header, unless that is taken or could be an index', () => {
  const ids = withColumnIds([
    { id: 'name', header: 'Name' },
    { header: 'Score' },
    { header: 'Score' },
    { header: 'name' },
    { header: '' },
    { header: '2' },
  ]).map(column => column.id);

  expect(ids).toEqual(['name', 'Score', undefined, undefined, undefined, undefined]);
});

it('keeps the sorting through a search', async () => {
  renderTable();
  fireEvent.click(screen.getByText('Score'));
  expect(names()).toEqual(['beta', 'gamma', 'alpha']);

  fireEvent.click(screen.getByRole('button', { name: 'Show/Hide search' }));
  fireEvent.change(screen.getByPlaceholderText('Search'), { target: { value: 'aa' } });
  // the search waits a moment for more typing; beta has one a
  await waitFor(() => expect(names()).toEqual(['gamma', 'alpha']));
  cleanup();

  // back on the page, as after opening a row of the results
  renderTable();
  expect(names()).toEqual(['beta', 'gamma', 'alpha']);
});

it('offers an action for the selected rows', () => {
  const onAction = vi.fn();
  render(
    <Provider store={store}>
      <ThemeProvider theme={createMuiTheme(lightTheme)}>
        <MemoryRouter>
          <Table
            data={data}
            columns={columns}
            enableRowSelection
            getRowId={item => item.name}
            renderRowSelectionToolbar={({ table }) => (
              <button
                onClick={() =>
                  onAction(table.getSelectedRowModel().rows.map(row => row.original.name))
                }
              >
                Act on selection
              </button>
            )}
          />
        </MemoryRouter>
      </ThemeProvider>
    </Provider>
  );
  expect(screen.queryByText('Act on selection')).toBeNull();

  const rowOf = (name: string) => screen.getByText(name).closest('tr')!;
  fireEvent.click(within(rowOf('alpha')).getByRole('checkbox'));
  fireEvent.click(within(rowOf('gamma')).getByRole('checkbox'));
  fireEvent.click(screen.getByText('Act on selection'));

  expect(onAction.mock.calls[0][0].sort()).toEqual(['alpha', 'gamma']);
});

it('passes a click on a row on, but not a click on a button in the row', () => {
  const onRowClick = vi.fn();
  const onButton = vi.fn();
  render(
    <Provider store={store}>
      <ThemeProvider theme={createMuiTheme(lightTheme)}>
        <MemoryRouter>
          <Table
            data={data}
            columns={[
              ...columns,
              {
                id: 'action',
                header: '',
                accessorFn: () => '',
                Cell: ({ row }: any) => (
                  <button onClick={() => onButton(row.original.name)}>Act</button>
                ),
              },
            ]}
            onRowClick={onRowClick}
          />
        </MemoryRouter>
      </ThemeProvider>
    </Provider>
  );

  fireEvent.click(screen.getByText('gamma'));
  expect(onRowClick).toHaveBeenCalledWith({ name: 'gamma', score: 2 });

  // the score cell of beta
  fireEvent.click(screen.getByText('3'));
  expect(onRowClick).toHaveBeenLastCalledWith({ name: 'beta', score: 3 });

  onRowClick.mockClear();
  fireEvent.click(screen.getAllByText('Act')[0]);
  expect(onButton).toHaveBeenCalled();
  expect(onRowClick).not.toHaveBeenCalled();
});

it('exports the rows as CSV from the toolbar of the table, beside its filters', () => {
  render(
    <Provider store={store}>
      <ThemeProvider theme={createMuiTheme(lightTheme)}>
        <MemoryRouter>
          <Table
            data={data}
            columns={columns}
            csvExport={{
              fileName: 'scores.csv',
              header: ['Name', 'Score'],
              rows: () => data.map(item => [item.name, item.score]),
            }}
            toolbarStart={<span>Filters</span>}
          />
        </MemoryRouter>
      </ThemeProvider>
    </Provider>
  );

  const button = screen.getByRole('button', { name: 'Export CSV' });
  // one line with the filters, above the rows
  const filters = screen.getByText('Filters');
  expect(filters.parentElement!.parentElement!.contains(button)).toBe(true);
  expect(button.compareDocumentPosition(screen.getByRole('table'))).toBe(
    Node.DOCUMENT_POSITION_FOLLOWING
  );
  fireEvent.click(button);

  expect(mocks.saveToFile).toHaveBeenCalledTimes(1);
  const [content, fileName] = mocks.saveToFile.mock.calls[0];
  expect(fileName).toBe('scores.csv');
  expect(content).toBe('Name,Score\r\nbeta,3\r\nalpha,1\r\ngamma,2\r\n');
});

it('keeps the filters when they leave no rows, which Headlamp shows without a toolbar', () => {
  render(
    <Provider store={store}>
      <ThemeProvider theme={createMuiTheme(lightTheme)}>
        <MemoryRouter>
          <Table
            data={[]}
            columns={columns}
            toolbarStart={<span>Filters</span>}
            csvExport={{ fileName: 'scores.csv', header: ['Name'], rows: () => [] }}
          />
        </MemoryRouter>
      </ThemeProvider>
    </Provider>
  );

  expect(screen.getByText('Filters')).toBeTruthy();
  expect(screen.getByText('No data to be shown.')).toBeTruthy();
  // nothing to export
  expect(screen.queryByRole('button', { name: 'Export CSV' })).toBeNull();
});

describe('rows per page', () => {
  const many = Array.from({ length: 30 }, (_, index) => ({ name: `row-${index}`, score: index }));
  const sizes = async () => {
    render(
      <Provider store={store}>
        <ThemeProvider theme={createMuiTheme(lightTheme)}>
          <MemoryRouter>
            <Table data={many} columns={columns} />
          </MemoryRouter>
        </ThemeProvider>
      </Provider>
    );
    fireEvent.mouseDown(screen.getByRole('combobox'));
    return (await screen.findAllByRole('option')).map(option => option.textContent);
  };

  afterEach(() => {
    // before the settings change, which a mounted table would follow
    cleanup();
    store.dispatch(setAppSettings({ tableRowsPerPageOptions: defaultTableRowsPerPageOptions }));
    localStorage.removeItem('settings');
    localStorage.removeItem('tables_rows_per_page');
  });

  it('offers the sizes of Headlamp, whose own tables take the size chosen in any table', async () => {
    expect(await sizes()).toEqual(['15', '25', '50']);

    // a size of the plugin's own would show in Headlamp's lists, which do not offer it
    fireEvent.click(screen.getByRole('option', { name: '50' }));
    expect(localStorage.getItem('tables_rows_per_page')).toBe('50');
  });

  it('offers the size the user added in the settings of Headlamp', async () => {
    store.dispatch(setAppSettings({ tableRowsPerPageOptions: [15, 25, 50, 200] }));
    expect(await sizes()).toEqual(['15', '25', '50', '200']);
  });
});
