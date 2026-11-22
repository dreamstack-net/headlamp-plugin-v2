/*
  Headlamp's table, which keeps the sorting for the session: back on a page, its tables are
  sorted the way the user left them.
*/
import {
  Table as HeadlampTable,
  TableColumn,
  TableProps,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Box } from '@mui/material';
import { MouseEvent, ReactNode, useMemo, useState } from 'react';
import { CsvExport, ExportCsvButton } from './ExportCsvButton';

export type SortingState = Array<{ id: string; desc: boolean }>;

// 2: the sorting names a column by its header instead of its index (withColumnIds)
const storagePrefix = 'kubescape.sorting.2.';

export function readSorting(key: string): SortingState | undefined {
  try {
    const saved = window.sessionStorage.getItem(storagePrefix + key);
    return saved ? JSON.parse(saved) : undefined;
  } catch {
    return undefined;
  }
}

function writeSorting(key: string, sorting: SortingState) {
  try {
    window.sessionStorage.setItem(storagePrefix + key, JSON.stringify(sorting));
  } catch {
    // the sorting is not kept when the storage is not available
  }
}

/** Identifies a table by its columns, so tables with the same columns share their sorting. */
export function sortingKeyOf<RowItem extends Record<string, any>>(
  columns: TableColumn<RowItem>[]
): string {
  return columns
    .map(column => column.id ?? (typeof column.header === 'string' ? column.header : ''))
    .join('|');
}

/**
 * The columns with an id of their own: their header, where they have none. Headlamp names a
 * column without an id by its index, so the sorting would move to another column when a column
 * appears before it, such as the Cluster column once a second cluster is selected. A header that
 * is taken, or that could be the index of another column, gives no id.
 */
export function withColumnIds<RowItem extends Record<string, any>>(
  columns: TableColumn<RowItem>[]
): TableColumn<RowItem>[] {
  const taken = new Set(columns.map(column => column.id));
  return columns.map(column => {
    const header = typeof column.header === 'string' ? column.header : '';
    if (column.id || !header || /^\d+$/.test(header) || taken.has(header)) return column;
    taken.add(header);
    return { ...column, id: header };
  });
}

/**
 * Whether a click on a cell is meant for its row: not for a button or link in the cell, not in a
 * menu that the cell opened, and not the end of selecting text.
 */
export function isRowClick(event: MouseEvent<HTMLElement>): boolean {
  const cell = event.currentTarget;
  const target = event.target as HTMLElement;
  // a menu or dialog the cell opened is not in the cell, though React passes its clicks on
  if (!cell.contains(target)) return false;
  const control = target.closest('button, a, input, [role="button"]');
  if (control && cell.contains(control)) return false;
  return !window.getSelection()?.toString();
}

/**
 * The columns with cells that pass a click to the row. Headlamp's table replaces the cell props
 * of the table with its own and gives its rows no box, so each cell takes the click.
 */
export function withRowClick<RowItem extends Record<string, any>>(
  columns: TableColumn<RowItem>[],
  onRowClick: (item: RowItem) => void
): TableColumn<RowItem>[] {
  return columns.map(column => {
    const own = column.muiTableBodyCellProps;
    const cellProps = (args: any) => {
      const props: any = (typeof own === 'function' ? own(args) : own) ?? {};
      return {
        ...props,
        onClick: (event: MouseEvent<HTMLTableCellElement>) => {
          props.onClick?.(event);
          if (isRowClick(event)) onRowClick(args.row.original);
        },
      };
    };
    // Headlamp reads the style of a column's cells from the props object
    const sx = typeof own === 'object' ? own?.sx : undefined;
    return { ...column, muiTableBodyCellProps: Object.assign(cellProps, { sx }) as any };
  });
}

const clickableRows = {
  '& tbody td': { cursor: 'pointer' },
  '& tbody tr:hover > td': { backgroundColor: 'action.hover' },
};

export default function Table<RowItem extends Record<string, any>>(
  props: TableProps<RowItem> & {
    // identifies the table, by default its columns
    sortingKey?: string;
    // offers the rows as a CSV file, with a button next to the table's own actions
    csvExport?: CsvExport;
    // controls for the rows, such as filter switches, at the start of the table's toolbar
    toolbarStart?: ReactNode;
    // makes the rows clickable, apart from the buttons and links in them
    onRowClick?: (item: RowItem) => void;
  }
) {
  const { sortingKey, csvExport, toolbarStart, onRowClick, ...tableProps } = props;
  const columns = useMemo(() => withColumnIds(tableProps.columns), [tableProps.columns]);
  const key = sortingKey ?? sortingKeyOf(tableProps.columns);
  const [sorting, setSorting] = useState<SortingState>(
    () => readSorting(key) ?? ((tableProps.initialState?.sorting ?? []) as SortingState)
  );

  // one line with the table's search and column buttons, instead of lines of their own
  const toolbar =
    csvExport || toolbarStart
      ? () => (
          <Box
            sx={{
              display: 'flex',
              flexGrow: 1,
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 1,
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
              {toolbarStart}
            </Box>
            {csvExport && <ExportCsvButton {...csvExport} />}
          </Box>
        )
      : tableProps.renderTopToolbarCustomActions;

  // a search keeps the sorting: to rank its results, the table clears the sorting while the search
  // box has text, which would be kept as the sorting the user chose. The rows per page are those
  // of Headlamp's settings: Headlamp keeps the size chosen in any table as that of all its tables,
  // so a size of the plugin's own would turn up in Headlamp's lists, whose choices lack it.
  const headlampTable = (
    <HeadlampTable
      enableGlobalFilterRankedResults={false}
      {...tableProps}
      columns={onRowClick ? withRowClick(columns, onRowClick) : columns}
      renderTopToolbarCustomActions={toolbar}
      state={{ ...tableProps.state, sorting }}
      onSortingChange={updater => {
        setSorting(previous => {
          const next = typeof updater === 'function' ? updater(previous) : updater;
          writeSorting(key, next);
          return next;
        });
      }}
    />
  );
  const table = onRowClick ? <Box sx={clickableRows}>{headlampTable}</Box> : headlampTable;

  // Headlamp shows an empty table as a message without the toolbar, which would take away the
  // filters that emptied it, so they stay above the message
  if (toolbarStart && !tableProps.data?.length && !tableProps.loading) {
    return (
      <>
        <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', mb: 1 }}>
          {toolbarStart}
        </Box>
        {table}
      </>
    );
  }
  return table;
}
