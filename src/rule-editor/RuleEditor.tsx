import { Icon } from '@iconify/react';
import { post, put, request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { SectionBox } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import Editor from '@monaco-editor/react';
import { TabContext, TabList } from '@mui/lab';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Divider,
  IconButton,
  Stack,
  Tab,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import * as yaml from 'js-yaml';
import { useEffect, useMemo, useRef, useState } from 'react';
import { errorMessage as messageOf } from '../common/errors';
import { AccessCheck, PermittedIconButton } from '../common/permissions';
import { TabPanel } from '../common/TabPanel';
import { useEditorTheme } from '../common/theme';
import { getURLSegments } from '../common/url';
import { Rule } from '../types/Rules';
import { isChartDefaultRules, useRulesNamespace } from './kubescapeNamespace';
import { PlaygroundDialog } from './PlaygroundDialog';
import { DEFAULT_NAMESPACE, EMPTY_RULE } from './ruleDefaults';
import { RuleForm } from './RuleForm';

export function RuleNew() {
  return <RuleFormPage />;
}

export function RuleEdit() {
  const [name, namespace] = getURLSegments(-1, -2);
  const [initialMeta, setInitialMeta] = useState<RuleMetadata | null>(null);
  const [initialRules, setInitialRules] = useState<Rule[] | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    setError('');
    request(`/apis/kubescape.io/v1/namespaces/${namespace}/rules/${name}`)
      .then((crd: any) => {
        if (!active) return;
        setInitialMeta({
          ...crd.metadata,
          name: crd.metadata.name,
          namespace: crd.metadata.namespace,
          resourceVersion: crd.metadata.resourceVersion,
        });
        setInitialRules(crd.spec?.rules?.length ? crd.spec.rules : [EMPTY_RULE]);
      })
      .catch((err: unknown) => {
        console.error('Failed to load rule:', err);
        if (active) setError(messageOf(err));
      });
    return () => {
      active = false;
    };
  }, [name, namespace]);

  if (error) {
    return (
      <SectionBox title="Edit Rule" backLink>
        <Alert severity="error">
          Unable to read the Rules object {namespace}/{name}: {error}
        </Alert>
      </SectionBox>
    );
  }
  if (!initialMeta || !initialRules) return null;
  return <RuleFormPage initialMeta={initialMeta} initialRules={initialRules} isEdit />;
}

// the metadata of a Rules object; the labels and annotations of one that was read are kept
type RuleMetadata = {
  name: string;
  namespace: string;
  resourceVersion?: string;
  [field: string]: any;
};

function RuleFormPage({
  initialMeta,
  initialRules,
  isEdit: openedForEdit = false,
}: Readonly<{
  initialMeta?: RuleMetadata;
  initialRules?: Rule[];
  isEdit?: boolean;
}>) {
  const editorTheme = useEditorTheme();
  const [ruleMeta, setRuleMeta] = useState<RuleMetadata>(
    initialMeta ?? {
      name: '',
      namespace: DEFAULT_NAMESPACE,
      resourceVersion: undefined,
    }
  );
  // the object in the cluster that a save replaces: the one the page was opened for, or the
  // one the page created
  const [savedMeta, setSavedMeta] = useState<RuleMetadata | undefined>(initialMeta);
  const isEdit = openedForEdit || !!savedMeta;
  const [rules, setRules] = useState<Rule[]>(initialRules ?? [EMPTY_RULE]);
  const ruleKeyCounter = useRef(0);
  const [ruleKeys, setRuleKeys] = useState<string[]>(() =>
    (initialRules ?? [EMPTY_RULE]).map(() => String(ruleKeyCounter.current++))
  );
  const [expanded, setExpanded] = useState<number>(0);
  const [tabValue, setTabValue] = useState(1);
  const [errorMessage, setErrorMessage] = useState('');
  const [saved, setSaved] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [playgroundOpen, setPlaygroundOpen] = useState(false);
  // the namespace of Kubescape in the current cluster, where the chart installs default-rules
  const kubescapeNamespace = useRulesNamespace();
  // a new Rules object goes to that namespace, unless the user chose another
  const namespaceChosen = useRef(false);
  useEffect(() => {
    if (!initialMeta && !savedMeta && !namespaceChosen.current) {
      setRuleMeta(meta => ({ ...meta, namespace: kubescapeNamespace }));
    }
  }, [kubescapeNamespace]); // eslint-disable-line react-hooks/exhaustive-deps

  const ruleYAML = useMemo(
    () =>
      yaml.dump({
        apiVersion: 'kubescape.io/v1',
        kind: 'Rules',
        metadata: { name: ruleMeta.name, namespace: ruleMeta.namespace },
        spec: { rules },
      }),
    [rules, ruleMeta]
  );

  const updateRule = <K extends keyof Rule>(idx: number, key: K, value: Rule[K]) => {
    setRules(rs => rs.map((r, i) => (i === idx ? { ...r, [key]: value } : r)));
    setSaved(false);
  };

  const addRule = () => {
    setRules(rs => [...rs, { ...EMPTY_RULE }]);
    setRuleKeys(ks => [...ks, String(ruleKeyCounter.current++)]);
    setExpanded(rules.length);
    setSaved(false);
  };

  const removeRule = (idx: number) => {
    setRules(rs => rs.filter((_, i) => i !== idx));
    setRuleKeys(ks => ks.filter((_, i) => i !== idx));
    setExpanded(Math.max(0, idx - 1));
    setSaved(false);
  };

  const handleSave = async () => {
    setSubmitted(true);
    if (!ruleMeta.name) return setErrorMessage('Name is required');
    for (const r of rules) {
      if (!r.name) return setErrorMessage('Every rule must have a name');
      if (!r.id) return setErrorMessage('Every rule must have an ID');
      if (!r.mitreTactic) return setErrorMessage(`Rule "${r.name || r.id}": Tactic is required`);
      if (!r.mitreTechnique)
        return setErrorMessage(`Rule "${r.name || r.id}": Technique is required`);
    }

    const body: any = {
      apiVersion: 'kubescape.io/v1',
      kind: 'Rules',
      metadata: {
        // labels and annotations, such as those of Helm or Argo CD, are kept
        ...savedMeta,
        name: savedMeta?.name ?? ruleMeta.name,
        namespace: savedMeta?.namespace ?? ruleMeta.namespace,
        ...(ruleMeta.resourceVersion ? { resourceVersion: ruleMeta.resourceVersion } : {}),
      },
      spec: { rules },
    };

    try {
      const written: any = savedMeta
        ? await put(
            `/apis/kubescape.io/v1/namespaces/${savedMeta.namespace}/rules/${savedMeta.name}`,
            body
          )
        : await post(`/apis/kubescape.io/v1/namespaces/${ruleMeta.namespace}/rules`, body);
      // the next save replaces what this one wrote, with its new version
      const metadata: RuleMetadata = {
        ...body.metadata,
        ...written?.metadata,
      };
      setSavedMeta(metadata);
      setRuleMeta(meta => ({ ...meta, resourceVersion: metadata.resourceVersion }));
      setErrorMessage('');
      setSaved(true);
    } catch (err) {
      setErrorMessage(messageOf(err));
    }
  };

  // the chart's default-rules, which Helm would overwrite
  const isReadOnly = openedForEdit && isChartDefaultRules(initialMeta, kubescapeNamespace);
  // an edit replaces the object it was opened from; a new one is created where the form says
  const saveNamespace = savedMeta?.namespace || ruleMeta.namespace;
  const saveCheck: AccessCheck | null = saveNamespace
    ? {
        group: 'kubescape.io',
        resource: 'rules',
        verb: savedMeta ? 'update' : 'create',
        namespace: saveNamespace,
        ...(savedMeta && { name: savedMeta.name }),
      }
    : null;

  return (
    <SectionBox backLink>
      <Stack direction="row" alignItems="center" sx={{ mt: 2, mb: 2 }} spacing={0}>
        <Typography variant="h4" sx={{ mr: 2, fontWeight: 'bold' }}>
          {isEdit ? 'Edit Rule' : 'New Rule'}
        </Typography>
        {!isReadOnly && (
          <PermittedIconButton
            check={saveCheck}
            title="Save to cluster"
            size="medium"
            onClick={handleSave}
          >
            <Icon icon="mdi:content-save" />
          </PermittedIconButton>
        )}
        <Tooltip title="Test rule in playground">
          <IconButton onClick={() => setPlaygroundOpen(true)}>
            <Icon icon="mdi:play-circle-outline" />
          </IconButton>
        </Tooltip>
      </Stack>

      {isReadOnly && (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          <Icon icon="mdi:lock-outline" style={{ verticalAlign: 'middle', marginRight: 4 }} />
          <strong>default-rules</strong> is system-managed and cannot be edited here. Deploy a
          custom Rules CRD to override individual rules.
        </Typography>
      )}

      <PlaygroundDialog
        open={playgroundOpen}
        onClose={() => setPlaygroundOpen(false)}
        rules={rules}
        ruleMeta={ruleMeta}
      />

      {errorMessage && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {errorMessage}
        </Alert>
      )}
      {saved && (
        <Alert severity="success" sx={{ mb: 2 }}>
          Saved successfully
        </Alert>
      )}

      <TabContext value={tabValue}>
        <TabList onChange={(_: any, v: number) => setTabValue(v)} sx={{ minHeight: 36 }}>
          <Tab label="Form" value={1} sx={{ minHeight: 36, py: 0 }} />
          <Tab label="YAML" value={2} sx={{ minHeight: 36, py: 0 }} />
        </TabList>
        <TabPanel value={1}>
          <Box>
            <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
              <TextField
                label="Name"
                value={ruleMeta.name}
                onChange={e => {
                  setRuleMeta(m => ({ ...m, name: e.target.value }));
                  setSaved(false);
                }}
                size="small"
                fullWidth
                required
                // a save replaces the object in the cluster, whose name cannot change
                disabled={isEdit}
                error={submitted && !ruleMeta.name}
              />
              <TextField
                label="Namespace"
                value={ruleMeta.namespace}
                onChange={e => {
                  namespaceChosen.current = true;
                  setRuleMeta(m => ({ ...m, namespace: e.target.value }));
                  setSaved(false);
                }}
                size="small"
                fullWidth
                disabled={isEdit}
              />
            </Stack>
            <Divider sx={{ mb: 2 }} />

            {/* Rules accordion */}
            {rules.map((r, idx) => (
              <Accordion
                key={ruleKeys[idx]}
                expanded={expanded === idx}
                onChange={() => setExpanded(expanded === idx ? -1 : idx)}
                sx={{ mb: 1 }}
              >
                <AccordionSummary expandIcon={<Icon icon="mdi:chevron-down" />}>
                  <Stack
                    direction="row"
                    alignItems="center"
                    spacing={2}
                    sx={{ width: '100%', pr: 1 }}
                  >
                    <Typography sx={{ fontWeight: 500 }}>{r.name || `Rule ${idx + 1}`}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {r.id}
                    </Typography>
                    <Box sx={{ flex: 1 }} />
                    {!isReadOnly && (
                      <IconButton
                        size="small"
                        onClick={e => {
                          e.stopPropagation();
                          removeRule(idx);
                        }}
                        disabled={rules.length <= 1}
                      >
                        <Icon icon="mdi:delete-outline" />
                      </IconButton>
                    )}
                  </Stack>
                </AccordionSummary>
                <AccordionDetails>
                  <RuleForm
                    rule={r}
                    onRuleChange={(key, value) => updateRule(idx, key, value)}
                    submitted={submitted}
                    readOnly={isReadOnly}
                  />
                </AccordionDetails>
              </Accordion>
            ))}
            {!isReadOnly && (
              <Button
                size="small"
                startIcon={<Icon icon="mdi:plus" />}
                onClick={addRule}
                sx={{ mt: 1 }}
              >
                Add rule
              </Button>
            )}
          </Box>
        </TabPanel>
        <TabPanel value={2}>
          <Editor
            language="yaml"
            value={ruleYAML}
            height={700}
            theme={editorTheme}
            options={{ readOnly: true, minimap: { enabled: false }, scrollBeyondLastLine: false }}
          />
        </TabPanel>
      </TabContext>
    </SectionBox>
  );
}
