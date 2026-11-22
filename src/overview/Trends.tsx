/*
  Failed controls and CVEs over time, from the Kubescape Prometheus exporter.
*/
import { Icon } from '@iconify/react';
import { Link as HeadlampLink, SectionBox } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import {
  Alert,
  Box,
  Button,
  Chip,
  Grid,
  IconButton,
  MenuItem,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
  useTheme,
} from '@mui/material';
import { ReactElement, useEffect, useState } from 'react';
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceArea,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { CompactTable } from '../common/CompactTable';
import { getPrometheusUrl, kubescapeConfigStore } from '../common/config-store';
import { errorMessage } from '../common/errors';
import { RoutingName, useHLSelectedClusters } from '../index';
import { dailyRows, detectPrometheus, fetchTrends, TrendKey, TrendRow } from './prometheus';
import {
  appearedOrWent,
  fetchScanSchedule,
  fetchTrendChanges,
  largestChange,
  lastScanStart,
  likelyCause,
  NamespaceChange,
  scanNear,
  ScanSchedule,
  TrendChanges,
  TrendInterval,
  TrendKind,
} from './trendChanges';

const ranges = [7, 30, 90];

// Categorical slots 1 and 2 of the chart palette, stepped for the light and dark surface
const seriesColors = {
  light: ['#2a78d6', '#eb6834'],
  dark: ['#3987e5', '#d95926'],
};

interface Series {
  key: TrendKey;
  label: string;
  color: string;
}

const compact = new Intl.NumberFormat(undefined, { notation: 'compact' });

function formatDate(time: number) {
  return new Date(time).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function formatTime(time: number) {
  return new Date(time).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function lastValue(rows: TrendRow[], key: TrendKey): { index: number; value: number } | null {
  for (let index = rows.length - 1; index >= 0; index--) {
    const value = rows[index][key];
    if (value !== undefined) return { index, value };
  }
  return null;
}

export function TrendsSection() {
  const clusters = useHLSelectedClusters();
  // re-render when the Prometheus address is configured
  kubescapeConfigStore.useConfig()();
  const prometheusUrl = getPrometheusUrl();
  const [chosenCluster, setChosenCluster] = useState(clusters[0]);
  const cluster = clusters.includes(chosenCluster) ? chosenCluster : clusters[0];
  const [days, setDays] = useState(30);
  // the rows with the cluster they are of: the rows of the cluster chosen before are not shown
  // under the name of another cluster while that one is read
  const [trends, setTrends] = useState<{ cluster: string; rows: TrendRow[] } | null>(null);
  const rows = trends?.cluster === cluster ? trends.rows : null;
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showTable, setShowTable] = useState(false);

  useEffect(() => {
    if (!prometheusUrl || !cluster) return;
    let active = true;
    setLoading(true);
    setError('');
    fetchTrends(cluster, days)
      .then(found => {
        if (active) setTrends({ cluster, rows: found });
      })
      .catch(err => {
        if (!active) return;
        setTrends(null);
        setError(errorMessage(err));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [prometheusUrl, cluster, days]);

  if (!prometheusUrl) {
    return (
      <SectionBox title="Trends">
        <PrometheusSuggestion cluster={cluster} />
      </SectionBox>
    );
  }

  return (
    <SectionBox title="Trends">
      <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2 }} flexWrap="wrap">
        <ToggleButtonGroup
          size="small"
          exclusive
          value={days}
          onChange={(_, value) => value && setDays(value)}
          aria-label="Time range"
        >
          {ranges.map(range => (
            <ToggleButton key={range} value={range}>
              Last {range} days
            </ToggleButton>
          ))}
        </ToggleButtonGroup>
        {clusters.length > 1 && (
          <TextField
            select
            size="small"
            label="Cluster"
            value={cluster}
            onChange={event => setChosenCluster(event.target.value)}
          >
            {clusters.map(name => (
              <MenuItem key={name} value={name}>
                {name}
              </MenuItem>
            ))}
          </TextField>
        )}
        {rows && rows.length > 0 && (
          <Button size="small" onClick={() => setShowTable(!showTable)}>
            {showTable ? 'Hide table' : 'Show table'}
          </Button>
        )}
      </Stack>

      {error && <Alert severity="error">Unable to read the trends from Prometheus: {error}</Alert>}
      {!error && rows === null && (
        <Typography variant="body2" color="text.secondary">
          Reading the trends…
        </Typography>
      )}
      {!error && rows?.length === 0 && <NoMetrics cluster={cluster} />}
      {!error && rows && rows.length > 0 && (
        // while another range of the cluster loads, the previous charts stay, dimmed
        <Box sx={{ opacity: loading ? 0.5 : 1, transition: 'opacity 0.2s' }}>
          <TrendCharts rows={rows} cluster={cluster} />
          {showTable && <TrendTable rows={rows} />}
        </Box>
      )}
    </SectionBox>
  );
}

// the change of a chart that its panel explains
interface Selection {
  kind: TrendKind;
  interval: TrendInterval;
}

function TrendCharts(props: Readonly<{ rows: TrendRow[]; cluster: string }>) {
  const { rows, cluster } = props;
  const theme = useTheme();
  const [critical, high] = seriesColors[theme.palette.mode === 'dark' ? 'dark' : 'light'];
  const [selection, setSelection] = useState<Selection | null>(null);

  // another range or cluster has other points
  useEffect(() => setSelection(null), [rows, cluster]);

  const select = (kind: TrendKind) => (interval: TrendInterval) => setSelection({ kind, interval });

  return (
    <>
      <Grid container spacing={4}>
        <Grid item xs={12} lg={6}>
          <TrendChart
            title="Failed controls"
            kind="controls"
            rows={rows}
            series={[
              { key: 'controlsCritical', label: 'Critical', color: critical },
              { key: 'controlsHigh', label: 'High', color: high },
            ]}
            selected={selection?.kind === 'controls' ? selection.interval : undefined}
            onSelect={select('controls')}
          />
        </Grid>
        <Grid item xs={12} lg={6}>
          <TrendChart
            title="CVEs"
            kind="cves"
            rows={rows}
            series={[
              { key: 'cvesCritical', label: 'Critical', color: critical },
              { key: 'cvesHigh', label: 'High', color: high },
            ]}
            selected={selection?.kind === 'cves' ? selection.interval : undefined}
            onSelect={select('cves')}
          />
        </Grid>
      </Grid>
      {selection && (
        <ChangePanel
          // a new panel for each change, so that the answer of an earlier one is not shown
          key={`${selection.kind}-${selection.interval.before}-${selection.interval.after}`}
          cluster={cluster}
          kind={selection.kind}
          interval={selection.interval}
          onClose={() => setSelection(null)}
        />
      )}
    </>
  );
}

function LineKey(props: Readonly<{ color: string }>) {
  return (
    <Box sx={{ width: 12, height: 2, borderRadius: 1, bgcolor: props.color, flexShrink: 0 }} />
  );
}

function TrendChart(
  props: Readonly<{
    title: string;
    kind: TrendKind;
    rows: TrendRow[];
    series: Series[];
    // the change whose namespaces the panel shows
    selected?: TrendInterval;
    onSelect: (interval: TrendInterval) => void;
  }>
) {
  const { title, kind, rows, series, selected, onSelect } = props;
  const largest = largestChange(rows, kind);
  const theme = useTheme();
  const muted = theme.palette.text.secondary;
  const surface = theme.palette.background.paper;

  const lasts = series.map(s => lastValue(rows, s.key));
  const max = Math.max(1, ...rows.flatMap(row => series.map(s => row[s.key] ?? 0)));
  // end labels that would touch each other are left to the legend
  const values = lasts.filter(last => last !== null).map(last => last!.value);
  const endLabels = values.every(
    (value, index) => index === 0 || Math.abs(value - values[index - 1]) > max * 0.08
  );

  return (
    <Box>
      <Typography variant="subtitle1" component="h3">
        {title}
      </Typography>
      <Stack direction="row" spacing={2} sx={{ mb: 1 }}>
        {series.map((s, index) => (
          <Stack key={s.key} direction="row" spacing={0.75} alignItems="center">
            <LineKey color={s.color} />
            <Typography variant="body2" color="text.secondary">
              {s.label}
            </Typography>
            {lasts[index] && (
              <Typography variant="body2" fontWeight="bold">
                {lasts[index]!.value.toLocaleString()}
              </Typography>
            )}
          </Stack>
        ))}
      </Stack>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Typography variant="caption" color="text.secondary">
          Choose a point to see which namespaces changed there, or
        </Typography>
        <Button
          size="small"
          disabled={!largest}
          onClick={() => largest && onSelect(largest)}
          sx={{ textTransform: 'none', py: 0 }}
        >
          explain the largest change
        </Button>
      </Stack>
      <ResponsiveContainer width="100%" height={240}>
        <LineChart
          data={rows}
          margin={{ top: 8, right: 40, bottom: 0, left: 0 }}
          // a click explains the largest change around the point it is nearest to
          onClick={(state: any) => {
            const index = state?.activeTooltipIndex;
            const interval =
              typeof index === 'number' ? largestChange(rows, kind, index) : undefined;
            if (interval) onSelect(interval);
          }}
          style={{ cursor: 'pointer' }}
        >
          <CartesianGrid vertical={false} stroke={theme.palette.divider} />
          {selected && (
            <ReferenceArea
              x1={selected.before}
              x2={selected.after}
              fill={muted}
              fillOpacity={0.15}
              ifOverflow="extendDomain"
            />
          )}
          <XAxis
            dataKey="time"
            type="number"
            scale="time"
            domain={['dataMin', 'dataMax']}
            tickFormatter={formatDate}
            stroke={theme.palette.divider}
            tick={{ fill: muted, fontSize: 12 }}
            tickLine={false}
            minTickGap={24}
          />
          <YAxis
            allowDecimals={false}
            domain={[0, 'auto']}
            tickFormatter={value => compact.format(value)}
            width={44}
            axisLine={false}
            tickLine={false}
            tick={{ fill: muted, fontSize: 12 }}
          />
          <Tooltip
            cursor={{ stroke: muted, strokeWidth: 1 }}
            content={({ active, payload, label }: any) =>
              active && payload?.length ? (
                <TrendTooltip time={label} series={series} row={payload[0].payload} />
              ) : null
            }
          />
          {series.map((s, index) => (
            <Line
              key={s.key}
              dataKey={s.key}
              name={s.label}
              stroke={s.color}
              strokeWidth={2}
              strokeLinejoin="round"
              strokeLinecap="round"
              dot={false}
              activeDot={{ r: 4, fill: s.color, stroke: surface, strokeWidth: 2 }}
              connectNulls
              isAnimationActive={false}
              label={(labelProps: any): ReactElement =>
                endLabels && labelProps.index === lasts[index]?.index ? (
                  <text
                    x={labelProps.x + 8}
                    y={labelProps.y}
                    dy={4}
                    fill={muted}
                    fontSize={12}
                    key={`${s.key}-end`}
                  >
                    {compact.format(labelProps.value)}
                  </text>
                ) : (
                  <g key={`${s.key}-${labelProps.index}`} />
                )
              }
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </Box>
  );
}

function TrendTooltip(props: Readonly<{ time: number; series: Series[]; row: TrendRow }>) {
  const { time, series, row } = props;
  return (
    <Paper elevation={3} sx={{ px: 1.5, py: 1 }}>
      <Typography variant="caption" color="text.secondary">
        {formatTime(time)}
      </Typography>
      {series.map(s => (
        <Stack key={s.key} direction="row" spacing={0.75} alignItems="center">
          <LineKey color={s.color} />
          <Typography variant="body2" fontWeight="bold">
            {row[s.key]?.toLocaleString() ?? '–'}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {s.label}
          </Typography>
        </Stack>
      ))}
    </Paper>
  );
}

/** The change of a total from one point to the other, red when it rose. */
function Delta(props: Readonly<{ before?: number; after?: number }>) {
  const diff = (props.after ?? 0) - (props.before ?? 0);
  let color = 'text.secondary';
  if (diff > 0) color = 'error.main';
  else if (diff < 0) color = 'success.main';
  return (
    <Box component="span" sx={{ color, fontWeight: 600, whiteSpace: 'nowrap' }}>
      {diff > 0 ? '+' : ''}
      {diff.toLocaleString()}
    </Box>
  );
}

function TotalChange(props: Readonly<{ before?: number; after?: number }>) {
  const { before, after } = props;
  return (
    <Stack direction="row" spacing={1} alignItems="baseline" component="span">
      <Box component="span" sx={{ whiteSpace: 'nowrap', fontVariantNumeric: 'tabular-nums' }}>
        {before?.toLocaleString() ?? '–'} → {after?.toLocaleString() ?? '–'}
      </Box>
      <Delta before={before} after={after} />
    </Stack>
  );
}

function hoursText(milliseconds: number): string {
  const hours = Math.round(milliseconds / 3600_000);
  if (hours < 1) return 'less than an hour';
  return `${hours} ${hours === 1 ? 'hour' : 'hours'}`;
}

/** When the daily scan of the chart ran, next to the interval. */
function ScanLine(
  props: Readonly<{ schedule: ScanSchedule; kind: TrendKind; interval: TrendInterval }>
) {
  const { schedule, kind, interval } = props;
  const what = kind === 'cves' ? 'vulnerability rescan of all images' : 'configuration scan';
  const start = lastScanStart(schedule, interval.after);
  if (start === undefined || schedule.hour === undefined || schedule.minute === undefined) {
    return (
      <Typography variant="body2" color="text.secondary">
        The {what} ({schedule.cronJob}) runs on the schedule {schedule.schedule}.
      </Typography>
    );
  }
  const at = `${String(schedule.hour).padStart(2, '0')}:${String(schedule.minute).padStart(
    2,
    '0'
  )} UTC`;
  return (
    <Typography variant="body2" color="text.secondary">
      The daily {what} ({schedule.cronJob}, {at}) last started {formatTime(start)}
      {start > interval.before
        ? ', within this interval.'
        : `, ${hoursText(interval.before - start)} before it.`}
    </Typography>
  );
}

// the namespaces the panel lists before Show all
const shownNamespaces = 10;

/**
 * Which namespaces changed between two points of a chart, from the namespace totals of the
 * exporter, with the time of the daily scan and what most likely caused the change.
 */
function ChangePanel(
  props: Readonly<{
    cluster: string;
    kind: TrendKind;
    interval: TrendInterval;
    onClose: () => void;
  }>
) {
  const { cluster, kind, interval, onClose } = props;
  const [found, setFound] = useState<TrendChanges | null>(null);
  const [schedule, setSchedule] = useState<ScanSchedule | undefined>();
  const [error, setError] = useState('');
  const [all, setAll] = useState(false);

  useEffect(() => {
    let active = true;
    fetchTrendChanges(cluster, kind, interval)
      .then(result => active && setFound(result))
      .catch(err => active && setError(errorMessage(err)));
    fetchScanSchedule(cluster, kind).then(result => active && setSchedule(result));
    return () => {
      active = false;
    };
  }, [cluster, kind, interval]);

  const what = kind === 'cves' ? 'CVEs' : 'failed controls';
  const sum = (pick: (item: NamespaceChange) => number | undefined) =>
    found?.changes.reduce((total, item) => total + (pick(item) ?? 0), 0) ?? 0;
  const shown = all ? found?.changes : found?.changes.slice(0, shownNamespaces);

  return (
    <Paper variant="outlined" sx={{ p: 2, mt: 3 }}>
      <Stack direction="row" spacing={1} alignItems="flex-start">
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="subtitle1" component="h3">
            What changed in the {what}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Between {formatTime(interval.before)} and {formatTime(interval.after)}, in {cluster}
          </Typography>
        </Box>
        <IconButton aria-label="Close" onClick={onClose}>
          <Icon icon="mdi:close" />
        </IconButton>
      </Stack>
      {error && (
        <Alert severity="error" sx={{ mt: 1 }}>
          Unable to read the totals of the namespaces from Prometheus: {error}
        </Alert>
      )}
      {!error && !found && (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          Reading the totals of the namespaces…
        </Typography>
      )}
      {found && (
        <Stack spacing={1} sx={{ mt: 1 }}>
          <Typography variant="body2" component="div">
            <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
              <span>
                Critical{' '}
                <Delta
                  before={sum(item => item.before.critical)}
                  after={sum(item => item.after.critical)}
                />
              </span>
              <span>
                High{' '}
                <Delta
                  before={sum(item => item.before.high)}
                  after={sum(item => item.after.high)}
                />
              </span>
              <span>
                in {found.changes.length} of {found.namespaceCount}{' '}
                {found.namespaceCount === 1 ? 'namespace' : 'namespaces'}
              </span>
            </Stack>
          </Typography>
          {schedule && <ScanLine schedule={schedule} kind={kind} interval={interval} />}
          <Alert severity="info" icon={<Icon icon="mdi:lightbulb-outline" />}>
            {likelyCause(found, kind, scanNear(schedule, interval))}
          </Alert>
          {found.changes.length > 0 && (
            <CompactTable
              rows={shown ?? []}
              rowKey={item => item.namespace}
              columns={[
                {
                  header: 'Namespace',
                  cell: item => {
                    const state = appearedOrWent(item);
                    return (
                      <Stack direction="row" spacing={1} alignItems="center">
                        {state === 'gone' ? (
                          <span>{item.namespace}</span>
                        ) : (
                          <HeadlampLink
                            routeName={
                              kind === 'cves'
                                ? RoutingName.VulnerabilitiesNamespaceSummary
                                : RoutingName.KubescapeConfigurationScanNamespaceSummary
                            }
                            params={{ namespace: item.namespace }}
                            activeCluster={cluster}
                          >
                            {item.namespace}
                          </HeadlampLink>
                        )}
                        {state && (
                          <Chip
                            size="small"
                            variant="outlined"
                            color={state === 'new' ? 'warning' : 'default'}
                            label={state}
                          />
                        )}
                      </Stack>
                    );
                  },
                },
                {
                  header: 'Critical',
                  cell: item => (
                    <TotalChange before={item.before.critical} after={item.after.critical} />
                  ),
                },
                {
                  header: 'High',
                  cell: item => <TotalChange before={item.before.high} after={item.after.high} />,
                },
              ]}
            />
          )}
          {!all && found.changes.length > shownNamespaces && (
            <Box>
              <Button size="small" onClick={() => setAll(true)}>
                Show all {found.changes.length} namespaces
              </Button>
            </Box>
          )}
        </Stack>
      )}
    </Paper>
  );
}

function TrendTable(props: Readonly<{ rows: TrendRow[] }>) {
  const columns: Array<[TrendKey, string]> = [
    ['controlsCritical', 'Critical failed controls'],
    ['controlsHigh', 'High failed controls'],
    ['cvesCritical', 'Critical CVEs'],
    ['cvesHigh', 'High CVEs'],
  ];
  return (
    <Table size="small" sx={{ mt: 2, fontVariantNumeric: 'tabular-nums' }}>
      <TableHead>
        <TableRow>
          <TableCell>Date</TableCell>
          {columns.map(([key, label]) => (
            <TableCell key={key} align="right">
              {label}
            </TableCell>
          ))}
        </TableRow>
      </TableHead>
      <TableBody>
        {dailyRows(props.rows)
          .reverse()
          .map(row => (
            <TableRow key={row.time}>
              <TableCell>{new Date(row.time).toLocaleDateString()}</TableCell>
              {columns.map(([key]) => (
                <TableCell key={key} align="right">
                  {row[key]?.toLocaleString() ?? '–'}
                </TableCell>
              ))}
            </TableRow>
          ))}
      </TableBody>
    </Table>
  );
}

function NoMetrics(props: Readonly<{ cluster: string }>) {
  return (
    <Alert severity="info">
      Prometheus has no Kubescape metrics for cluster {props.cluster}. Enable the Prometheus
      exporter of the Kubescape operator, with a ServiceMonitor when Prometheus is run by the
      Prometheus operator:
      <Box component="pre" sx={{ whiteSpace: 'pre-wrap', mt: 1, mb: 0 }}>
        helm upgrade kubescape kubescape/kubescape-operator -n kubescape --reuse-values --set
        capabilities.prometheusExporter=enable --set prometheusExporter.serviceMonitor.enabled=true
      </Box>
      The trends start when Prometheus has scraped the exporter.
    </Alert>
  );
}

// Offers to use the Prometheus found in the cluster while none is configured
function PrometheusSuggestion(props: Readonly<{ cluster: string }>) {
  const { cluster } = props;
  const [addresses, setAddresses] = useState<string[] | null>(null);

  useEffect(() => {
    let active = true;
    detectPrometheus(cluster)
      .catch(() => [])
      .then(found => {
        if (active) setAddresses(found);
      });
    return () => {
      active = false;
    };
  }, [cluster]);

  return (
    <Alert severity="info">
      Trends of failed controls and CVEs come from the Kubescape Prometheus exporter. Set the
      address of Prometheus in the Kubescape plugin settings.
      {addresses && addresses.length > 0 && (
        <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 1 }} flexWrap="wrap">
          <span>Found in cluster {cluster}:</span>
          {addresses.map(address => (
            <Chip
              key={address}
              label={`Use ${address}`}
              size="small"
              onClick={() => kubescapeConfigStore.update({ prometheusUrl: address })}
            />
          ))}
        </Stack>
      )}
    </Alert>
  );
}
