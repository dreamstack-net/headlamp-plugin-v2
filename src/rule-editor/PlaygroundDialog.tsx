// The dialog that tests rules against a mock event and profile with the RuleEval WASM function.
import { Icon } from '@iconify/react';
import { TabContext, TabList } from '@mui/lab';
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogContent,
  DialogTitle,
  IconButton,
  MenuItem,
  Stack,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import * as yaml from 'js-yaml';
import { useCallback, useEffect, useRef, useState } from 'react';
import { errorMessage } from '../common/errors';
import { TabPanel } from '../common/TabPanel';
import { defaultEventData, EventType, Rule, RuleEvalResults } from '../types/Rules';
import { useWasm } from '../wasm/initWasmModule';
import { ClusterMockLoader, LoadMeta } from './ClusterMockLoader';
import { CodeEditor, MonacoEditor } from './MonacoEditor';
import {
  EMPTY_K8S_YAML,
  EMPTY_NETWORK_YAML,
  EMPTY_PROFILE_YAML,
  EVENT_TYPES,
} from './ruleDefaults';
import type { RuleEvaluator } from './ruleValidation';

export type RuleTestResult = {
  rule: Rule;
  evalResult: RuleEvalResults | null;
  evalError: string;
};

export type RuleOutcome = 'disabled' | 'error' | 'N/A' | 'fired' | 'not fired';

/**
 * What a rule does with the event: like the node-agent, it fires when every expression of the
 * event type is true, not when one of them is.
 */
export function ruleOutcome(item: RuleTestResult): RuleOutcome | null {
  if (item.rule.enabled === false) return 'disabled';
  if (item.evalError || item.evalResult?.error) return 'error';
  if (item.evalResult?.eventTypeMismatch) return 'N/A';
  if (!item.evalResult) return null;
  const fired =
    item.evalResult.fired ??
    // an evaluator that does not answer it yet
    ((item.evalResult.ruleExpression ?? []).length > 0 &&
      item.evalResult.ruleExpression.every(r => r.result === true));
  return fired ? 'fired' : 'not fired';
}

/**
 * The message of a rule that fired; the evaluator does not evaluate it otherwise. A rule whose
 * expressions are all true does not alert when its unique id fails, as the node-agent sends
 * no alert without one: the reason is shown instead.
 */
export function firedMessage(item: RuleTestResult): string {
  const outcome = ruleOutcome(item);
  const result = item.evalResult;
  const expressions = result?.ruleExpression ?? [];
  if (
    outcome === 'not fired' &&
    result?.uniqueId?.error &&
    expressions.length > 0 &&
    expressions.every(expression => expression.result === true)
  ) {
    return `No alert, as the unique id failed: ${result.uniqueId.error}`;
  }
  if (outcome === 'not fired' && result?.prefiltered) return result.prefiltered;
  if (outcome !== 'fired') return '';
  const message = item.evalResult?.message;
  return message?.error ? `The message failed: ${message.error}` : message?.result ?? '';
}

const outcomeColors: Record<RuleOutcome, 'default' | 'error' | 'warning' | 'success'> = {
  disabled: 'default',
  error: 'error',
  'N/A': 'default',
  fired: 'warning',
  'not fired': 'success',
};

function ruleChip(item: RuleTestResult) {
  const outcome = ruleOutcome(item);
  return outcome && <Chip label={outcome} color={outcomeColors[outcome]} size="small" />;
}

export function PlaygroundDialog({
  open,
  onClose,
  rules,
  ruleMeta,
}: Readonly<{
  open: boolean;
  onClose: () => void;
  rules: Rule[];
  ruleMeta: { name: string; namespace: string };
}>) {
  const wasm = useWasm();

  const [eventType, setEventType] = useState<EventType>('exec');
  const [eventData, setEventData] = useState(JSON.stringify(defaultEventData.exec, null, 2));
  const [profileYAML, setProfileYAML] = useState(EMPTY_PROFILE_YAML);
  const [networkYAML, setNetworkYAML] = useState(EMPTY_NETWORK_YAML);
  const [k8sYAML, setK8sYAML] = useState(EMPTY_K8S_YAML);
  const [results, setResults] = useState<RuleTestResult[]>([]);
  const [hideNA, setHideNA] = useState(true);
  const [mockTabValue, setMockTabValue] = useState(1);
  const eventEditorRef = useRef<CodeEditor | null>(null);
  const profileEditorRef = useRef<CodeEditor | null>(null);
  const networkEditorRef = useRef<CodeEditor | null>(null);

  const patchEventData = (meta: LoadMeta) => {
    if (!meta.containerName && !meta.namespace && !meta.workload) return;
    try {
      const parsed = JSON.parse(eventData);
      if (meta.containerName) {
        parsed.containerId = meta.containerName;
        parsed.containerName = meta.containerName;
      }
      if (meta.namespace) parsed.namespace = meta.namespace;
      if (meta.workload) parsed.podName = meta.workload;
      const updated = JSON.stringify(parsed, null, 2);
      setEventData(updated);
      eventEditorRef.current?.setValue(updated);
    } catch {
      // malformed event data — skip
    }
  };

  const onEventTypeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const et = e.target.value as EventType;
    setEventType(et);
    const newEventData = JSON.stringify(defaultEventData[et] ?? {}, null, 2);
    setEventData(newEventData);
    eventEditorRef.current?.setValue(newEventData);
    setResults([]);
  };

  const evaluate = useCallback(() => {
    if (!window.RuleEval) {
      setResults([]);
      return;
    }
    const next: RuleTestResult[] = rules.map(rule => {
      if (rule.enabled === false) return { rule, evalResult: null, evalError: '' };
      const singleYAML = yaml.dump({
        apiVersion: 'kubescape.io/v1',
        kind: 'Rules',
        metadata: ruleMeta,
        spec: { rules: [rule] },
      });
      try {
        const ruleEval: RuleEvaluator = window.RuleEval;
        const evalResult: RuleEvalResults = JSON.parse(
          ruleEval(singleYAML, eventType, eventData, profileYAML, networkYAML, k8sYAML)
        );
        return { rule, evalResult, evalError: '' };
      } catch (err) {
        return { rule, evalResult: null, evalError: errorMessage(err) };
      }
    });
    setResults(next);
  }, [rules, ruleMeta, eventType, eventData, profileYAML, networkYAML, k8sYAML]);

  // again once the evaluator is loaded
  useEffect(() => {
    if (open) evaluate();
  }, [open, wasm.ready]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (open) evaluate();
  }, [eventType]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Stack direction="row" alignItems="center" justifyContent="space-between">
          <span>Test Rules</span>
          <IconButton size="small" onClick={onClose}>
            <Icon icon="mdi:close" />
          </IconButton>
        </Stack>
      </DialogTitle>
      <DialogContent>
        <Typography variant="subtitle2" sx={{ mb: 0.5 }}>
          Event Data
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          The runtime event that triggered the rule — for example an exec call, a file open, or a
          network connection. Select the event type to load a template, then edit the fields to
          match the scenario you want to test.
        </Typography>
        <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 1 }}>
          <TextField
            select
            value={eventType}
            onChange={onEventTypeChange}
            label="Event type"
            size="small"
            sx={{ minWidth: 140 }}
          >
            {EVENT_TYPES.map(et => (
              <MenuItem key={et} value={et}>
                {et}
              </MenuItem>
            ))}
          </TextField>
        </Stack>

        {/* the dialog makes its editors anew each time it opens: with what was entered before,
            which is what it evaluates */}
        <MonacoEditor
          editorRef={eventEditorRef}
          language="json"
          defaultValue={eventData}
          height={200}
          onChange={v => {
            setEventData(v);
            setResults([]);
          }}
        />

        <Typography variant="subtitle2" sx={{ mt: 2, mb: 0.5 }}>
          Baseline mock data
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          Rules that use <code>cp.*</code> functions (or the older <code>ap.*</code> and{' '}
          <code>nn.*</code>) compare the event against a learned baseline. Populate these mocks to
          simulate what the baseline contains — leave them empty to simulate a container with no
          baseline activity. The <code>k8s.*</code> functions read the Kubernetes mock.
        </Typography>
        <TabContext value={mockTabValue}>
          <TabList onChange={(_: any, v: number) => setMockTabValue(v)} sx={{ minHeight: 36 }}>
            <Tab label="ApplicationProfile mock" value={1} sx={{ minHeight: 36, py: 0 }} />
            <Tab label="NetworkNeighborhood mock" value={2} sx={{ minHeight: 36, py: 0 }} />
            <Tab label="Kubernetes mock" value={3} sx={{ minHeight: 36, py: 0 }} />
          </TabList>
          <TabPanel value={1}>
            <ClusterMockLoader
              baselineKind="application"
              onLoad={(v, meta) => {
                setProfileYAML(v);
                profileEditorRef.current?.setValue(v);
                patchEventData(meta);
                setResults([]);
              }}
            />
            <MonacoEditor
              editorRef={profileEditorRef}
              language="yaml"
              defaultValue={profileYAML}
              height={150}
              onChange={v => {
                setProfileYAML(v);
                setResults([]);
              }}
            />
          </TabPanel>
          <TabPanel value={2}>
            <ClusterMockLoader
              baselineKind="network"
              onLoad={(v, meta) => {
                setNetworkYAML(v);
                networkEditorRef.current?.setValue(v);
                patchEventData(meta);
                setResults([]);
              }}
            />
            <MonacoEditor
              editorRef={networkEditorRef}
              language="yaml"
              defaultValue={networkYAML}
              height={150}
              onChange={v => {
                setNetworkYAML(v);
                setResults([]);
              }}
            />
          </TabPanel>
          <TabPanel value={3}>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              The API server address of <code>k8s.is_api_server_address</code>, and the pods whose
              containers <code>k8s.get_container_mount_paths</code> and{' '}
              <code>k8s.get_container_by_name</code> read, with the fields of Pod objects. The
              command and the exec commands of the lifecycle hooks of the event&apos;s container
              count as executed for <code>cp.was_executed</code>, as in the node-agent.
            </Typography>
            <MonacoEditor
              language="yaml"
              defaultValue={k8sYAML}
              height={150}
              onChange={v => {
                setK8sYAML(v);
                setResults([]);
              }}
            />
          </TabPanel>
        </TabContext>

        {wasm.error && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            The rules cannot be evaluated: {wasm.error}
          </Alert>
        )}
        <Box sx={{ mt: 2, mb: results.length ? 2 : 0 }}>
          {/* not before the evaluator is loaded, without which there is nothing to show */}
          <Button variant="contained" onClick={evaluate} disabled={!wasm.ready}>
            Evaluate
          </Button>
        </Box>

        {results.length > 0 &&
          (() => {
            const errors = results.flatMap(item => {
              const msg =
                item.evalError ||
                item.evalResult?.error ||
                item.evalResult?.ruleExpression?.find(r => r.error)?.error;
              return msg ? [`${item.rule.name}: ${msg}`] : [];
            });

            if (errors.length > 0) {
              return (
                <Box sx={{ mt: 2 }}>
                  {errors.map((e, i) => (
                    <Alert key={i} severity="error" sx={{ mb: 1 }}>
                      {e}
                    </Alert>
                  ))}
                </Box>
              );
            }

            return (
              <>
                <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
                  <Button
                    size="small"
                    variant={hideNA ? 'contained' : 'outlined'}
                    onClick={() => setHideNA(h => !h)}
                  >
                    {hideNA ? 'Show N/A' : 'Hide N/A'}
                  </Button>
                </Stack>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Result</TableCell>
                      <TableCell>Message</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {results
                      .filter(item => !hideNA || !item.evalResult?.eventTypeMismatch)
                      .map((item, idx) => (
                        <TableRow key={idx}>
                          <TableCell>{item.rule.name}</TableCell>
                          <TableCell>{ruleChip(item)}</TableCell>
                          <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                            {firedMessage(item)}
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </>
            );
          })()}
      </DialogContent>
    </Dialog>
  );
}
