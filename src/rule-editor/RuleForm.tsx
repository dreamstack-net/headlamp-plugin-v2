import { Icon } from '@iconify/react';
import {
  Alert,
  Box,
  Divider,
  FormControl,
  FormControlLabel,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import Autocomplete from '@mui/material/Autocomplete';
import { useEffect, useRef, useState } from 'react';
import { errorMessage } from '../common/errors';
import { EventType, ProfileDependency, Rule, RuleExpression } from '../types/Rules';
import { useWasm } from '../wasm/initWasmModule';
import { LibraryReferenceButton } from './LibraryReference';
import { EVENT_TYPES, MITRE_TACTICS, MITRE_TECHNIQUES } from './ruleDefaults';
import { isExpressionError, RuleSyntaxErrors, ruleSyntaxErrors } from './ruleValidation';

/** The tags of a rule, typed as text separated by commas; the text is kept while it is typed. */
function TagsField(props: Readonly<{ tags: string[]; onChange: (tags: string[]) => void }>) {
  const { tags, onChange } = props;
  const [text, setText] = useState(tags.join(', '));
  const parse = (value: string) =>
    value
      .split(',')
      .map(tag => tag.trim())
      .filter(Boolean);
  // the tags changed elsewhere, such as in the YAML
  useEffect(() => {
    if (parse(text).join('\u0000') !== tags.join('\u0000')) setText(tags.join(', '));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tags.join('\u0000')]);
  return (
    <TextField
      label="Tags (comma-separated)"
      value={text}
      onChange={e => {
        setText(e.target.value);
        onChange(parse(e.target.value));
      }}
      size="small"
      fullWidth
      sx={{ mb: 2 }}
    />
  );
}

export function RuleForm({
  rule,
  onRuleChange,
  submitted,
  readOnly = false,
}: Readonly<{
  rule: Rule;
  onRuleChange: <K extends keyof Rule>(key: K, value: Rule[K]) => void;
  submitted: boolean;
  readOnly?: boolean;
}>) {
  const setExpr = (patch: Partial<Rule['expressions']>) =>
    onRuleChange('expressions', { ...rule.expressions, ...patch });

  const exprKeyCounter = useRef(0);
  const exprKeys = useRef<string[]>(
    rule.expressions.ruleExpression.map(() => String(exprKeyCounter.current++))
  );

  const updateExpression = (idx: number, field: keyof RuleExpression, value: string) => {
    const exprs = [...rule.expressions.ruleExpression];
    exprs[idx] = { ...exprs[idx], [field]: value };
    setExpr({ ruleExpression: exprs });
  };

  const addExpression = () => {
    exprKeys.current.push(String(exprKeyCounter.current++));
    setExpr({
      ruleExpression: [
        ...rule.expressions.ruleExpression,
        { eventType: 'exec' as EventType, expression: '' },
      ],
    });
  };

  const removeExpression = (idx: number) => {
    exprKeys.current.splice(idx, 1);
    setExpr({
      ruleExpression: rule.expressions.ruleExpression.filter((_, i) => i !== idx),
    });
  };

  const [syntaxErrors, setSyntaxErrors] = useState<RuleSyntaxErrors>({ expressions: [] });

  const wasm = useWasm();

  // the expressions are checked a moment after the user stops typing, once the evaluator is
  // loaded
  useEffect(() => {
    if (!wasm.ready) return;
    const timeout = setTimeout(() => {
      try {
        setSyntaxErrors(ruleSyntaxErrors(rule, window.RuleEval));
      } catch (error) {
        setSyntaxErrors({ expressions: [], rule: errorMessage(error) });
      }
    }, 400);
    return () => clearTimeout(timeout);
  }, [rule.expressions, wasm.ready]); // eslint-disable-line react-hooks/exhaustive-deps

  const row = { mb: 2 };
  const mono = { style: { fontFamily: 'monospace', fontSize: 13 } };

  return (
    <Box
      component={readOnly ? 'fieldset' : 'div'}
      disabled={readOnly}
      sx={{ border: 0, p: 0, m: 0 }}
    >
      <Stack direction="row" spacing={2} sx={row}>
        <TextField
          label="Name"
          value={rule.name}
          onChange={e => onRuleChange('name', e.target.value)}
          size="small"
          fullWidth
          required
          error={submitted && !rule.name}
        />
        <TextField
          label="ID"
          value={rule.id}
          onChange={e => onRuleChange('id', e.target.value)}
          size="small"
          sx={{ minWidth: 110 }}
          required
          error={submitted && !rule.id}
        />
      </Stack>
      <TextField
        label="Description"
        value={rule.description}
        onChange={e => onRuleChange('description', e.target.value)}
        size="small"
        fullWidth
        multiline
        rows={2}
        sx={row}
      />

      {/* Toggles */}
      <Stack direction="row" spacing={3} sx={row}>
        <FormControlLabel
          control={
            <Switch
              color="primary"
              checked={rule.enabled}
              onChange={e => onRuleChange('enabled', e.target.checked)}
              size="small"
            />
          }
          label="Enabled"
        />
        <FormControlLabel
          control={
            <Switch
              color="primary"
              checked={rule.isTriggerAlert}
              onChange={e => onRuleChange('isTriggerAlert', e.target.checked)}
              size="small"
            />
          }
          label="Trigger alert"
        />
        <FormControlLabel
          control={
            <Switch
              color="primary"
              checked={rule.supportPolicy}
              onChange={e => onRuleChange('supportPolicy', e.target.checked)}
              size="small"
            />
          }
          label="Support policy"
        />
      </Stack>

      {/* Severity */}
      <TextField
        label="Severity (1–10)"
        type="number"
        value={rule.severity}
        onChange={e => {
          const next = Number(e.target.value);
          if (!Number.isFinite(next)) return;
          onRuleChange('severity', Math.min(10, Math.max(1, next)));
        }}
        size="small"
        sx={{ ...row, width: 160 }}
        inputProps={{ min: 1, max: 10 }}
      />

      {/* Profile dependency */}
      <FormControl size="small" sx={{ ...row, minWidth: 220 }}>
        <InputLabel>Profile dependency</InputLabel>
        <Select
          label="Profile dependency"
          value={rule.profileDependency}
          onChange={e =>
            onRuleChange('profileDependency', Number(e.target.value) as ProfileDependency)
          }
        >
          <MenuItem value={0}>Required</MenuItem>
          <MenuItem value={1}>Optional</MenuItem>
          <MenuItem value={2}>Not required</MenuItem>
        </Select>
      </FormControl>

      <Divider sx={{ mb: 2 }} />

      <Stack direction="row" spacing={2} sx={row}>
        <Autocomplete
          freeSolo
          options={MITRE_TACTICS}
          getOptionLabel={o => (typeof o === 'string' ? o : `${o.id} — ${o.name}`)}
          inputValue={rule.mitreTactic}
          filterOptions={(options, { inputValue }) => {
            const isStoredId = options.some(o => o.id === inputValue);
            if (!inputValue || isStoredId) return options;
            const q = inputValue.toLowerCase();
            return options.filter(
              o => o.id.toLowerCase().includes(q) || o.name.toLowerCase().includes(q)
            );
          }}
          onInputChange={(_, v, reason) => {
            if (reason !== 'reset') onRuleChange('mitreTactic', v);
          }}
          onChange={(_, v) =>
            onRuleChange('mitreTactic', typeof v === 'string' ? v : v ? v.id : '')
          }
          size="small"
          fullWidth
          renderInput={params => (
            <TextField
              {...params}
              label="Tactic"
              required
              error={submitted && !rule.mitreTactic}
              helperText={submitted && !rule.mitreTactic ? 'Required' : ''}
              placeholder="e.g. TA0002"
            />
          )}
        />
        <Autocomplete
          freeSolo
          options={MITRE_TECHNIQUES}
          getOptionLabel={o => (typeof o === 'string' ? o : `${o.id} — ${o.name}`)}
          inputValue={rule.mitreTechnique}
          filterOptions={(options, { inputValue }) => {
            const isStoredId = options.some(o => o.id === inputValue);
            if (!inputValue || isStoredId) return options;
            const q = inputValue.toLowerCase();
            return options.filter(
              o => o.id.toLowerCase().includes(q) || o.name.toLowerCase().includes(q)
            );
          }}
          onInputChange={(_, v, reason) => {
            if (reason !== 'reset') onRuleChange('mitreTechnique', v);
          }}
          onChange={(_, v) =>
            onRuleChange('mitreTechnique', typeof v === 'string' ? v : v ? v.id : '')
          }
          size="small"
          fullWidth
          renderInput={params => (
            <TextField
              {...params}
              label="Technique"
              required
              error={submitted && !rule.mitreTechnique}
              helperText={submitted && !rule.mitreTechnique ? 'Required' : ''}
              placeholder="e.g. T1059"
            />
          )}
        />
      </Stack>

      {/* Tags */}
      <TagsField tags={rule.tags ?? []} onChange={tags => onRuleChange('tags', tags)} />

      <Divider sx={{ mb: 2 }} />

      {(syntaxErrors.rule || wasm.error) && (
        <Alert severity="warning" sx={row}>
          The expressions could not be checked: {syntaxErrors.rule ?? wasm.error}
        </Alert>
      )}
      <TextField
        label="Message"
        value={rule.expressions.message}
        onChange={e => setExpr({ message: e.target.value })}
        size="small"
        fullWidth
        sx={row}
        inputProps={mono}
        error={isExpressionError(syntaxErrors.message)}
        helperText={syntaxErrors.message}
      />
      <TextField
        label="Unique ID"
        value={rule.expressions.uniqueId}
        onChange={e => setExpr({ uniqueId: e.target.value })}
        size="small"
        fullWidth
        sx={row}
        inputProps={mono}
        error={isExpressionError(syntaxErrors.uniqueId)}
        helperText={syntaxErrors.uniqueId}
      />

      <Stack direction="row" alignItems="center" spacing={0.5} sx={{ mb: 1 }}>
        <Typography variant="body2">Rule expressions</Typography>
        <LibraryReferenceButton />
      </Stack>
      {rule.expressions.ruleExpression.map((expr, idx) => (
        <Box
          key={exprKeys.current[idx]}
          sx={{ mb: 2, pl: 1, borderLeft: '3px solid', borderColor: 'divider' }}
        >
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
            <TextField
              select
              label="Event type"
              value={expr.eventType}
              onChange={e => updateExpression(idx, 'eventType', e.target.value)}
              size="small"
              sx={{ minWidth: 150 }}
            >
              {EVENT_TYPES.map(et => (
                <MenuItem key={et} value={et}>
                  {et}
                </MenuItem>
              ))}
            </TextField>
            <Box sx={{ flex: 1 }} />
            {!readOnly && (
              <IconButton
                size="small"
                onClick={() => removeExpression(idx)}
                disabled={rule.expressions.ruleExpression.length <= 1}
              >
                <Icon icon="mdi:delete-outline" />
              </IconButton>
            )}
          </Stack>
          <TextField
            value={expr.expression}
            onChange={e => updateExpression(idx, 'expression', e.target.value)}
            size="small"
            fullWidth
            placeholder="CEL expression"
            multiline
            minRows={2}
            inputProps={mono}
            error={isExpressionError(syntaxErrors.expressions[idx])}
            helperText={syntaxErrors.expressions[idx]}
            InputProps={{ readOnly }}
          />
        </Box>
      ))}
      {!readOnly && (
        <IconButton size="small" onClick={addExpression} sx={{ mt: 0.5 }}>
          <Icon icon="mdi:plus-circle-outline" />
        </IconButton>
      )}
    </Box>
  );
}
