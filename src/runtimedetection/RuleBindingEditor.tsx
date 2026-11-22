import { Icon } from '@iconify/react';
import { post, put, request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { SectionBox } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Divider,
  IconButton,
  MenuItem,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import { useEffect, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { errorMessage as messageOf } from '../common/errors';
import { Permitted } from '../common/permissions';
import { getURLSegments } from '../common/url';

const SEVERITIES = ['', 'Critical', 'High', 'Medium', 'Low'];
const API_PATH = '/apis/kubescape.io/v1/runtimerulealertbindings';

export type LabelEntry = { key: string; value: string };
export type ExprEntry = { key: string; operator: string; values: string };
// a rule of the binding; original is the rule as it was, whose other fields (ruleID, ruleTags,
// parameters such as the ignored mounts of a file rule) are kept while it names the same rule
export type RuleEntry = { ruleName: string; severity: string; original?: Record<string, any> };

/** How a rule that is bound by its id or tags rather than its name is named in the form. */
function ruleReference(rule: RuleEntry): string | undefined {
  if (rule.ruleName.trim() || !rule.original) return undefined;
  if (rule.original.ruleID) return `Rule ID ${rule.original.ruleID}`;
  if (rule.original.ruleTags?.length) return `Rules tagged ${rule.original.ruleTags.join(', ')}`;
  return undefined;
}

/** The rule as it is saved: the fields of the form over those it had. */
export function ruleToSave(rule: RuleEntry): Record<string, any> {
  const name = rule.ruleName.trim();
  const original = rule.original ?? {};
  // a rule that was replaced by another name keeps nothing of the one it was
  const kept = !name || name === (original.ruleName ?? '') ? { ...original } : {};
  delete kept.severity;
  if (name) kept.ruleName = name;
  return { ...kept, ...(rule.severity ? { severity: rule.severity } : {}) };
}

const OPERATORS = ['In', 'NotIn', 'Exists', 'DoesNotExist'];

function labelsToEntries(matchLabels: Record<string, string> | undefined): LabelEntry[] {
  return Object.entries(matchLabels ?? {}).map(([key, value]) => ({ key, value }));
}

function expressionsToEntries(matchExpressions: any[] | undefined): ExprEntry[] {
  return (matchExpressions ?? []).map(e => ({
    key: e.key ?? '',
    operator: e.operator ?? 'In',
    values: (e.values ?? []).join(', '),
  }));
}

function entriesToMatchLabels(entries: LabelEntry[]): Record<string, string> {
  return Object.fromEntries(entries.filter(e => e.key).map(e => [e.key, e.value]));
}

export interface BindingFormValues {
  name: string;
  nsLabels: LabelEntry[];
  nsExpressions: ExprEntry[];
  podLabels: LabelEntry[];
  podExpressions: ExprEntry[];
  rules: RuleEntry[];
}

/**
 * The binding as it is saved: the fields of the form over the binding as it was read, whose
 * labels, annotations and resourceVersion (such as those of Helm or Argo CD) and other fields
 * are kept.
 */
export function bindingToSave(existing: any, form: BindingFormValues): any {
  return {
    ...existing,
    apiVersion: 'kubescape.io/v1',
    kind: 'RuntimeRuleAlertBinding',
    metadata: {
      ...existing?.metadata,
      name: form.name.trim(),
    },
    spec: {
      ...existing?.spec,
      namespaceSelector: {
        matchLabels: entriesToMatchLabels(form.nsLabels),
        ...(form.nsExpressions.length
          ? { matchExpressions: entriesToMatchExpressions(form.nsExpressions) }
          : {}),
      },
      podSelector: {
        matchLabels: entriesToMatchLabels(form.podLabels),
        ...(form.podExpressions.length
          ? { matchExpressions: entriesToMatchExpressions(form.podExpressions) }
          : {}),
      },
      rules: form.rules.map(ruleToSave),
    },
  };
}

function entriesToMatchExpressions(entries: ExprEntry[]): any[] {
  return entries
    .filter(e => e.key)
    .map(e => ({
      key: e.key,
      operator: e.operator,
      ...(e.operator === 'In' || e.operator === 'NotIn'
        ? {
            values: e.values
              .split(',')
              .map(v => v.trim())
              .filter(Boolean),
          }
        : {}),
    }));
}

function SelectorEditor({
  label,
  labels,
  expressions,
  onLabelsChange,
  onExpressionsChange,
}: Readonly<{
  label: string;
  labels: LabelEntry[];
  expressions: ExprEntry[];
  onLabelsChange: (v: LabelEntry[]) => void;
  onExpressionsChange: (v: ExprEntry[]) => void;
}>) {
  const updateLabel = (idx: number, field: 'key' | 'value', val: string) =>
    onLabelsChange(labels.map((e, i) => (i === idx ? { ...e, [field]: val } : e)));
  const addLabel = () => onLabelsChange([...labels, { key: '', value: '' }]);
  const removeLabel = (idx: number) => onLabelsChange(labels.filter((_, i) => i !== idx));

  const updateExpr = (idx: number, field: keyof ExprEntry, val: string) =>
    onExpressionsChange(expressions.map((e, i) => (i === idx ? { ...e, [field]: val } : e)));
  const addExpr = () =>
    onExpressionsChange([...expressions, { key: '', operator: 'In', values: '' }]);
  const removeExpr = (idx: number) => onExpressionsChange(expressions.filter((_, i) => i !== idx));

  const isEmpty = labels.length === 0 && expressions.length === 0;

  return (
    <Box>
      <Typography variant="subtitle2" sx={{ mb: 0.5 }}>
        {label}
      </Typography>
      {isEmpty && (
        <Typography variant="caption" color="text.secondary">
          No selector — matches all
        </Typography>
      )}

      {/* matchLabels */}
      {labels.length > 0 && (
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
          matchLabels
        </Typography>
      )}
      {labels.map((e, idx) => (
        <Stack key={idx} direction="row" spacing={1} sx={{ mb: 0.5 }}>
          <TextField
            size="small"
            label="Key"
            value={e.key}
            onChange={ev => updateLabel(idx, 'key', ev.target.value)}
            sx={{ flex: 1 }}
          />
          <TextField
            size="small"
            label="Value"
            value={e.value}
            onChange={ev => updateLabel(idx, 'value', ev.target.value)}
            sx={{ flex: 1 }}
          />
          <IconButton size="small" onClick={() => removeLabel(idx)}>
            <Icon icon="mdi:delete-outline" />
          </IconButton>
        </Stack>
      ))}

      {/* matchExpressions */}
      {expressions.length > 0 && (
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ display: 'block', mb: 0.5, mt: labels.length ? 1 : 0 }}
        >
          matchExpressions
        </Typography>
      )}
      {expressions.map((e, idx) => (
        <Stack key={idx} direction="row" spacing={1} sx={{ mb: 0.5 }} alignItems="center">
          <TextField
            size="small"
            label="Key"
            value={e.key}
            onChange={ev => updateExpr(idx, 'key', ev.target.value)}
            sx={{ flex: 2 }}
          />
          <TextField
            select
            size="small"
            label="Operator"
            value={e.operator}
            onChange={ev => updateExpr(idx, 'operator', ev.target.value)}
            sx={{ flex: 1, minWidth: 130 }}
          >
            {OPERATORS.map(op => (
              <MenuItem key={op} value={op}>
                {op}
              </MenuItem>
            ))}
          </TextField>
          {(e.operator === 'In' || e.operator === 'NotIn') && (
            <TextField
              size="small"
              label="Values (comma-separated)"
              value={e.values}
              onChange={ev => updateExpr(idx, 'values', ev.target.value)}
              sx={{ flex: 2 }}
            />
          )}
          <IconButton size="small" onClick={() => removeExpr(idx)}>
            <Icon icon="mdi:delete-outline" />
          </IconButton>
        </Stack>
      ))}

      <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
        <Tooltip title="Add matchLabel">
          <Button size="small" startIcon={<Icon icon="mdi:plus" />} onClick={addLabel}>
            Label
          </Button>
        </Tooltip>
        <Tooltip title="Add matchExpression">
          <Button size="small" startIcon={<Icon icon="mdi:plus" />} onClick={addExpr}>
            Expression
          </Button>
        </Tooltip>
      </Stack>
    </Box>
  );
}

function RuleBindingForm({
  initialName = '',
  initialNsLabels = [],
  initialNsExpressions = [],
  initialPodLabels = [],
  initialPodExpressions = [],
  initialRules = [],
  existing,
  isEdit = false,
}: Readonly<{
  initialName?: string;
  initialNsLabels?: LabelEntry[];
  initialNsExpressions?: ExprEntry[];
  initialPodLabels?: LabelEntry[];
  initialPodExpressions?: ExprEntry[];
  initialRules?: RuleEntry[];
  // the binding as it was read, whose metadata and other fields are kept
  existing?: any;
  isEdit?: boolean;
}>) {
  const history = useHistory();
  const [name, setName] = useState(initialName);
  const [nsLabels, setNsLabels] = useState<LabelEntry[]>(initialNsLabels);
  const [nsExpressions, setNsExpressions] = useState<ExprEntry[]>(initialNsExpressions);
  const [podLabels, setPodLabels] = useState<LabelEntry[]>(initialPodLabels);
  const [podExpressions, setPodExpressions] = useState<ExprEntry[]>(initialPodExpressions);
  const [rules, setRules] = useState<RuleEntry[]>(initialRules);
  const [errorMessage, setErrorMessage] = useState('');
  const [availableRuleNames, setAvailableRuleNames] = useState<string[]>([]);

  // Fetch available rule names from Rules CRDs for autocomplete
  useEffect(() => {
    request('/apis/kubescape.io/v1/rules')
      .then((res: any) => {
        const names: string[] = (res.items ?? []).flatMap((crd: any) =>
          (crd.spec?.rules ?? []).map((r: any) => r.name ?? r.id).filter(Boolean)
        );
        setAvailableRuleNames([...new Set(names)]);
      })
      .catch(() => {});
  }, []);

  const addRule = () => setRules(r => [...r, { ruleName: '', severity: '' }]);
  const removeRule = (idx: number) => setRules(r => r.filter((_, i) => i !== idx));
  const updateRule = (idx: number, field: keyof RuleEntry, val: string) =>
    setRules(r => r.map((e, i) => (i === idx ? { ...e, [field]: val } : e)));

  const handleSave = async () => {
    if (!name.trim()) return setErrorMessage('Name is required');
    if (rules.some(r => !r.ruleName.trim() && !ruleReference(r))) {
      return setErrorMessage('All rules must have a name');
    }
    const hasEmptyInNotIn = [...nsExpressions, ...podExpressions].some(
      e =>
        (e.operator === 'In' || e.operator === 'NotIn') &&
        e.values
          .split(',')
          .map((v: string) => v.trim())
          .filter(Boolean).length === 0
    );
    if (hasEmptyInNotIn) return setErrorMessage('In/NotIn expressions require at least one value');

    const body = bindingToSave(existing, {
      name,
      nsLabels,
      nsExpressions,
      podLabels,
      podExpressions,
      rules,
    });

    try {
      if (isEdit) {
        await put(`${API_PATH}/${name.trim()}`, body);
      } else {
        await post(API_PATH, body);
      }
      history.goBack();
    } catch (err) {
      setErrorMessage(messageOf(err));
    }
  };

  return (
    <SectionBox backLink title={isEdit ? 'Edit Rule Binding' : 'New Rule Binding'}>
      <Stack spacing={3} sx={{ maxWidth: 700, mt: 2 }}>
        {errorMessage && <Alert severity="error">{errorMessage}</Alert>}

        <TextField
          label="Name"
          value={name}
          onChange={e => setName(e.target.value)}
          size="small"
          required
          disabled={isEdit}
          fullWidth
        />

        <Divider />

        <SelectorEditor
          label="Namespace Selector"
          labels={nsLabels}
          expressions={nsExpressions}
          onLabelsChange={setNsLabels}
          onExpressionsChange={setNsExpressions}
        />

        <SelectorEditor
          label="Pod Selector"
          labels={podLabels}
          expressions={podExpressions}
          onLabelsChange={setPodLabels}
          onExpressionsChange={setPodExpressions}
        />

        <Divider />

        <Box>
          <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
            <Typography variant="subtitle2" sx={{ flex: 1 }}>
              Rules
            </Typography>
            <Tooltip title="Add rule">
              <IconButton size="small" onClick={addRule}>
                <Icon icon="mdi:plus" />
              </IconButton>
            </Tooltip>
          </Stack>
          {rules.length === 0 && (
            <Typography variant="caption" color="text.secondary">
              No rules bound yet
            </Typography>
          )}
          {rules.map((r, idx) => (
            <Stack key={idx} direction="row" spacing={1} sx={{ mb: 1 }} alignItems="center">
              <Autocomplete
                freeSolo
                options={availableRuleNames}
                value={r.ruleName}
                onInputChange={(_, val) => updateRule(idx, 'ruleName', val)}
                renderInput={params => (
                  <TextField
                    {...params}
                    size="small"
                    label="Rule Name"
                    required={!ruleReference(r)}
                    placeholder={ruleReference(r)}
                    helperText={ruleReference(r)}
                  />
                )}
                sx={{ flex: 2 }}
              />
              <TextField
                select
                size="small"
                label="Severity"
                value={r.severity}
                onChange={e => updateRule(idx, 'severity', e.target.value)}
                sx={{ flex: 1, minWidth: 120 }}
              >
                {SEVERITIES.map(s => (
                  <MenuItem key={s} value={s}>
                    {s || '(default)'}
                  </MenuItem>
                ))}
              </TextField>
              <IconButton size="small" onClick={() => removeRule(idx)}>
                <Icon icon="mdi:delete-outline" />
              </IconButton>
            </Stack>
          ))}
        </Box>

        <Stack direction="row" spacing={1}>
          <Permitted
            check={{
              group: 'kubescape.io',
              resource: 'runtimerulealertbindings',
              verb: isEdit ? 'update' : 'create',
              ...(isEdit && { name: name.trim() }),
            }}
          >
            {allowed => (
              <Button variant="contained" disabled={!allowed} onClick={handleSave}>
                Save
              </Button>
            )}
          </Permitted>
          <Button onClick={() => history.goBack()}>Cancel</Button>
        </Stack>
      </Stack>
    </SectionBox>
  );
}

export function RuleBindingNew() {
  return <RuleBindingForm />;
}

export function RuleBindingEdit() {
  const [name] = getURLSegments(-1);
  const [binding, setBinding] = useState<any>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    request(`${API_PATH}/${name}`)
      .then((b: any) => active && setBinding(b))
      .catch((err: unknown) => active && setError(messageOf(err)));
    return () => {
      active = false;
    };
  }, [name]);

  if (error) return <Alert severity="error">{error}</Alert>;
  if (!binding) return null;

  return (
    <RuleBindingForm
      initialName={name}
      initialNsLabels={labelsToEntries(binding.spec?.namespaceSelector?.matchLabels)}
      initialNsExpressions={expressionsToEntries(binding.spec?.namespaceSelector?.matchExpressions)}
      initialPodLabels={labelsToEntries(binding.spec?.podSelector?.matchLabels)}
      initialPodExpressions={expressionsToEntries(binding.spec?.podSelector?.matchExpressions)}
      initialRules={(binding.spec?.rules ?? []).map((r: any) => ({
        ruleName: r.ruleName ?? '',
        severity: r.severity ?? '',
        original: r,
      }))}
      existing={binding}
      isEdit
    />
  );
}
