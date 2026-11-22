import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import Editor from '@monaco-editor/react';
import { TabContext, TabList } from '@mui/lab';
import { Alert, Grid, Stack, Tab, Toolbar, Typography } from '@mui/material';
import * as yaml from 'js-yaml';
import { createContext, useContext, useEffect, useRef, useState } from 'react';
import { errorMessage } from '../common/errors';
import { TabPanel } from '../common/TabPanel';
import { useEditorTheme } from '../common/theme';
import type { CodeEditor } from '../rule-editor/MonacoEditor';
import { ValidatingAdmissionPolicy } from '../types/ValidatingAdmissionPolicy';
import { loadWasm, useWasm } from '../wasm/initWasmModule';
import { ChoosePolicyButton } from './ChoosePolicyButton';
import { ChooseTestResource } from './ChooseTestResource';
import { EvaluationResults, EvaluationResultsTables } from './EvaluationResultsTables';
import { InstallPolicyButton } from './InstallPolicyButton';
import { useSampleParams } from './samples';

type EvalContext = {
  resource: any;
  setResource: (resource: any) => void;
  setResourceForNamespace: (namespace: any) => void;
  paramsObject: any;
  namespaceObject: any;
  validatingAdmissionPolicy: ValidatingAdmissionPolicy | null;
  setValidatingAdmissionPolicy: (policy: any) => void;
};

export const CurrentEvalContext = createContext<EvalContext | null>(null);

/** The context of the playground, which its editor provides to the parts in it. */
export function useEvalContext(): EvalContext {
  const context = useContext(CurrentEvalContext);
  if (!context) throw new Error('The policy playground provides this context');
  return context;
}

export function ValidatingAdmissionPolicyEditor() {
  const wasm = useWasm();

  const [validatingAdmissionPolicy, setValidatingAdmissionPolicy] =
    useState<ValidatingAdmissionPolicy | null>(null);
  const [namespaceObject, setNamespaceObject] = useState<any | null>(null);
  const [resource, setResource] = useState<any>(null);
  const [resourceForNamespace, setResourceForNamespace] = useState<any | null>(null);

  // the sample parameters, if the policy reads parameters
  const { params: paramsObject, error: paramsError } = useSampleParams(validatingAdmissionPolicy);

  // Get namespace, if defined in resource
  useEffect(() => {
    let active = true;
    if (resourceForNamespace?.metadata?.namespace) {
      request(`/api/v1/namespaces/${encodeURIComponent(resourceForNamespace.metadata.namespace)}`)
        .then((result: any) => {
          if (active) setNamespaceObject(result);
        })
        // a namespace that cannot be read is not the namespace of an earlier resource
        .catch(() => {
          if (active) setNamespaceObject(null);
        });
    } else {
      setNamespaceObject(null);
    }
    return () => {
      active = false;
    };
  }, [resourceForNamespace]);

  return (
    <CurrentEvalContext.Provider
      value={{
        resource,
        setResource,
        setResourceForNamespace,
        paramsObject,
        namespaceObject,
        validatingAdmissionPolicy,
        setValidatingAdmissionPolicy,
      }}
    >
      <Toolbar>
        <Stack spacing={2} sx={{ mt: 2 }}>
          <Typography variant="h5" component="div">
            Policy Playground
          </Typography>
          <Typography component="div">
            Choose a sample Validating Admission Policy and a test resource, a sample or one from
            the cluster. You can also edit the policy or the test resource and observe calculated
            results in the tables below. Install in cluster tries the policy on real requests,
            warning about violations without rejecting them.
          </Typography>
        </Stack>
      </Toolbar>

      {wasm.error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          The policy evaluator could not be loaded: {wasm.error}
        </Alert>
      )}
      {paramsError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {paramsError}
        </Alert>
      )}
      <AdmissionEvaluator />
    </CurrentEvalContext.Provider>
  );
}

// how long the editors must be left alone before the policy is evaluated
const EVALUATION_DELAY_MS = 300;

function AdmissionEvaluator() {
  const {
    resource,
    paramsObject,
    namespaceObject,
    validatingAdmissionPolicy,
    setResourceForNamespace,
  } = useEvalContext();
  const [evaluationResult, setEvaluationResult] = useState<EvaluationResults | null>(null);
  // whether the policy editor holds text, a sample that was chosen or a policy that was typed
  const [policyEntered, setPolicyEntered] = useState(false);

  // Editors
  const policyEditorRef = useRef<CodeEditor | null>(null);
  const resourceEditorRef = useRef<CodeEditor | null>(null);
  const paramsEditorRef = useRef<CodeEditor | null>(null);
  const namespaceEditorRef = useRef<CodeEditor | null>(null);

  // Tab switching
  const [policyTabValue, setPolicyTabValue] = useState(1);
  const [resourceTabValue, setResourceTabValue] = useState(1);

  // Evaluating parses the YAML of all editors and compiles the CEL expressions of the policy, so
  // it runs once typing pauses rather than on every key
  const evaluationTimer = useRef<number | undefined>(undefined);
  const scheduleEvaluation = () => {
    setPolicyEntered((policyEditorRef.current?.getValue() ?? '').trim() !== '');
    window.clearTimeout(evaluationTimer.current);
    evaluationTimer.current = window.setTimeout(() => {
      submitEvaluation();
    }, EVALUATION_DELAY_MS);
  };
  useEffect(() => () => window.clearTimeout(evaluationTimer.current), []);

  const submitEvaluation = async () => {
    const policy = policyEditorRef.current?.getValue() ?? '';
    const testResource = resourceEditorRef.current?.getValue() ?? '';
    // there is nothing to evaluate until the editors hold a policy and a resource, whether they
    // were chosen or typed
    if (!policy.trim() || !testResource.trim()) {
      setEvaluationResult(null);
      return;
    }
    try {
      await loadWasm();
      // call golang WASM module
      const response = window.AdmissionEval(
        policy,
        testResource,
        '',
        '',
        paramsEditorRef.current?.getValue() ?? '',
        namespaceEditorRef.current?.getValue() ?? ''
      );
      setEvaluationResult(JSON.parse(response));
    } catch (error) {
      setEvaluationResult({ error: errorMessage(error), matchConstraints: false });
    }
  };

  return (
    <>
      <Grid container spacing={8}>
        <Grid container item xs={6} direction="column">
          <Toolbar>
            <Stack direction="row" spacing={1} alignItems="center">
              <ChoosePolicyButton />
              <InstallPolicyButton
                disabled={!policyEntered}
                getPolicyYaml={() => policyEditorRef.current?.getValue()}
                getParamsYaml={() => paramsEditorRef.current?.getValue()}
              />
            </Stack>
          </Toolbar>
          <TabContext value={policyTabValue}>
            <TabList
              onChange={(event: React.SyntheticEvent, newValue: number) => {
                setPolicyTabValue(newValue);
              }}
            >
              <Tab label="Policy" value={1} />
              <Tab label="Params" value={2} />
            </TabList>

            <TabPanel value={1}>
              <YAMLEditor
                editorRef={policyEditorRef}
                submitFn={scheduleEvaluation}
                value={yaml.dump(stripK8sObject(validatingAdmissionPolicy))}
              />
            </TabPanel>
            <TabPanel value={2}>
              <YAMLEditor
                editorRef={paramsEditorRef}
                submitFn={scheduleEvaluation}
                value={yaml.dump(stripK8sObject(paramsObject))}
              />
            </TabPanel>
          </TabContext>
        </Grid>

        <Grid container item xs={6} direction="column">
          <Toolbar>
            <ChooseTestResource />
          </Toolbar>
          <TabContext value={resourceTabValue}>
            <TabList
              onChange={(event: React.SyntheticEvent, newValue: number) => {
                setResourceTabValue(newValue);
              }}
            >
              <Tab label="Resource" value={1} />
              <Tab label="Namespace" value={2} />
            </TabList>

            <TabPanel value={1}>
              <YAMLEditor
                editorRef={resourceEditorRef}
                handleChange={setResourceForNamespace}
                submitFn={scheduleEvaluation}
                value={yaml.dump(stripK8sObject(resource))}
              />
            </TabPanel>
            <TabPanel value={2}>
              <YAMLEditor
                editorRef={namespaceEditorRef}
                submitFn={scheduleEvaluation}
                value={yaml.dump(stripK8sObject(namespaceObject))}
              />
            </TabPanel>
          </TabContext>
        </Grid>
      </Grid>
      <EvaluationResultsTables evaluationResult={evaluationResult} />
    </>
  );
}

function YAMLEditor(props: {
  editorRef: React.MutableRefObject<CodeEditor | null>;
  submitFn: () => void;
  value: string;
  // receives the parsed YAML once it is valid
  handleChange?: (value: unknown) => void;
}) {
  const { editorRef, submitFn, value, handleChange } = props;
  const editorTheme = useEditorTheme();
  const lastCodeCheckHandler = useRef(0);

  const [errors, setErrors] = useState('');

  // request validation of policy and resources
  const onChange = () => {
    // Clear any ongoing attempts to check the code.
    window.clearTimeout(lastCodeCheckHandler.current);

    // Check the YAML after the user has stopped typing for a second.
    lastCodeCheckHandler.current = window.setTimeout(() => {
      let parsed: unknown;
      try {
        parsed = yaml.load(editorRef.current?.getValue() ?? '');
      } catch (e) {
        setErrors(errorMessage(e));
        return;
      }

      setErrors('');
      handleChange?.(parsed);
    }, 1000); // ms

    // the evaluator waits for typing to pause itself
    submitFn();
  };

  // the YAML check and the namespace lookup are not for an editor that is gone
  useEffect(() => () => window.clearTimeout(lastCodeCheckHandler.current), []);

  return (
    <>
      <Editor
        language="yaml"
        onMount={editor => {
          editorRef.current = editor;
          editor.onDidChangeModelContent(onChange);
        }}
        theme={editorTheme}
        value={value}
        height={600}
      />
      {errors && (
        <Alert variant="outlined" severity="error">
          {errors}
        </Alert>
      )}
    </>
  );
}

function stripK8sObject(k8sObject: any): any {
  if (!k8sObject) {
    return undefined;
  }
  // strip status
  const strippedResource: any = Object.fromEntries(
    Object.entries(k8sObject).filter(([key]) => key !== 'status')
  );

  if (strippedResource.metadata) {
    // strip managedFields
    strippedResource.metadata = Object.fromEntries(
      Object.entries(strippedResource.metadata).filter(([key]) => key !== 'managedFields')
    );

    // strip last-applied from annotations
    if (strippedResource.metadata.annotations)
      strippedResource.metadata.annotations = Object.fromEntries(
        Object.entries(strippedResource.metadata.annotations).filter(
          ([key]) => key !== 'kubectl.kubernetes.io/last-applied-configuration'
        )
      );
  }
  return strippedResource;
}
