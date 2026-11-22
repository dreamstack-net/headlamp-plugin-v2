import { ShowHideLabel } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { TabContext, TabList } from '@mui/lab';
import { Alert, Box, Tab, Table, TableBody, TableCell, TableHead, TableRow } from '@mui/material';
import { useState } from 'react';
import { TabPanel } from '../common/TabPanel';
import { useDarkMode } from '../common/theme';

interface EvalResult {
  name: string;
  expression?: string;
  // a boolean, a string or what the expression gave as JSON
  result?: unknown;
  error?: string;
  message?: string;
}

/** What the WASM evaluator answers; the fields are left out when they are empty. */
export interface EvaluationResults {
  // the policy, the resource or the other input could not be read
  error?: string;
  variables?: EvalResult[];
  matchConditions?: EvalResult[];
  matchConstraints: boolean;
  // why the request does not match the constraints
  matchReason?: string;
  // false when a match condition is false, so the API server skips the policy
  matchConditionsMatched?: boolean;
  // a match condition that failed while none is false, for which the API server applies the
  // failurePolicy
  matchConditionError?: string;
  failurePolicyIgnore?: boolean;
  validations?: EvalResult[];
  auditAnnotations?: EvalResult[];
  // an audit annotation for which the API server rejects the request, whatever the
  // validationActions of the binding
  auditAnnotationError?: string;
}

// what the validationActions of a binding do with a request that violates the policy
const validationActions =
  'a binding with Deny rejects the request, Warn returns a warning and Audit records it in ' +
  'the audit log';

const tabs = [
  { value: 1, label: 'Variables', results: (r: EvaluationResults) => r.variables },
  { value: 2, label: 'Match Conditions', results: (r: EvaluationResults) => r.matchConditions },
  { value: 3, label: 'Validations', results: (r: EvaluationResults) => r.validations },
  { value: 4, label: 'Audit Annotations', results: (r: EvaluationResults) => r.auditAnnotations },
];

/** What the API server does with the request, as far as the policy decides it. */
function Summary(props: Readonly<{ evaluationResult: EvaluationResults }>) {
  const { evaluationResult: result } = props;
  const ignore = !!result.failurePolicyIgnore;

  // the API server skips the policy when a match condition is false
  if (result.matchConditionsMatched === false) {
    return <p>A match condition is false, so the policy does not apply to the resource.</p>;
  }
  if (result.matchConditionError) {
    return (
      <Alert severity={ignore ? 'info' : 'error'}>
        The match condition {result.matchConditionError}.{' '}
        {ignore
          ? 'The failurePolicy of the policy is Ignore, so the API server admits the request.'
          : `The failurePolicy of the policy is Fail, the default, so the API server treats the request as a violation: ${validationActions}.`}
      </Alert>
    );
  }

  const validations = result.validations ?? [];
  const failed = validations.filter(v => v.error).length;
  const violated = validations.filter(v => !v.error && v.result !== true).length;
  return (
    <>
      {result.auditAnnotationError && (
        <Alert severity="error" sx={{ mb: 1 }}>
          The audit annotation {result.auditAnnotationError}. The API server rejects the request for
          it, whatever the validationActions of the binding.
        </Alert>
      )}
      {failed > 0 && (
        <Alert severity={ignore ? 'info' : 'error'} sx={{ mb: 1 }}>
          {failed === 1 ? 'A validation failed' : `${failed} validations failed`}.{' '}
          {ignore
            ? 'The failurePolicy of the policy is Ignore, so the API server admits the request for it.'
            : `The failurePolicy of the policy is Fail, the default, so the API server treats that as a violation: ${validationActions}.`}
        </Alert>
      )}
      {violated > 0 && <p>The resource violates the policy: {validationActions}.</p>}
      {failed === 0 && violated === 0 && <p>The resource is valid.</p>}
    </>
  );
}

export function EvaluationResultsTables(props: { evaluationResult: EvaluationResults | null }) {
  const { evaluationResult } = props;
  // the tab the user chose, null for the one that matters most
  const [chosenTab, setChosenTab] = useState<number | null>(null);

  if (!evaluationResult) return null;
  if (evaluationResult.error) {
    return (
      <Alert severity="error">The policy could not be evaluated: {evaluationResult.error}</Alert>
    );
  }
  if (!evaluationResult.matchConstraints) {
    return (
      <p>
        The resource does not match.
        {evaluationResult.matchReason ? ` ${evaluationResult.matchReason}` : ''}
      </p>
    );
  }

  const available = tabs.filter(tab => tab.results(evaluationResult)?.length);
  // the validations, else the audit annotations, else what there is
  const preferred = [3, 4, 2, 1].find(value => available.some(tab => tab.value === value));
  const tabValue =
    chosenTab !== null && available.some(tab => tab.value === chosenTab) ? chosenTab : preferred;

  return (
    <>
      <Summary evaluationResult={evaluationResult} />
      {tabValue !== undefined && (
        <TabContext value={String(tabValue)}>
          <TabList
            onChange={(event: React.SyntheticEvent, newValue: string) => {
              setChosenTab(Number(newValue));
            }}
          >
            {tabs.map(tab => (
              <Tab
                key={tab.value}
                label={tab.label}
                disabled={!available.includes(tab)}
                value={String(tab.value)}
              />
            ))}
          </TabList>
          {tabs.map(tab => (
            <TabPanel key={tab.value} value={String(tab.value)}>
              <EvaluationResult results={tab.results(evaluationResult)} />
            </TabPanel>
          ))}
        </TabContext>
      )}
    </>
  );
}

function resultText(result: unknown): string {
  if (result === undefined || result === null) return '';
  return typeof result === 'object' ? JSON.stringify(result) : String(result);
}

function EvaluationResult(props: { results?: EvalResult[] }) {
  const { results } = props;

  const bgColor = useDarkMode() ? 'black' : 'white';

  return (
    <Box sx={{ pt: 2 }}>
      <Table>
        <TableHead>
          <TableRow sx={{ backgroundColor: bgColor }}>
            <TableCell>Name</TableCell>
            <TableCell>Expression</TableCell>
            <TableCell>Result</TableCell>
            <TableCell>Message</TableCell>
            <TableCell>Error</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {results?.map(result => (
            <TableRow key={result.name}>
              <TableCell style={{ width: '10%' }} component="th" scope="row">
                {result.name}
              </TableCell>
              <TableCell style={{ width: '25%' }}>
                <ShowHideLabel>{result.expression ?? ''}</ShowHideLabel>
              </TableCell>
              <TableCell style={{ width: '20%' }}>{resultText(result.result)}</TableCell>
              <TableCell style={{ width: '25%' }}>{result.message}</TableCell>
              <TableCell style={{ width: '20%' }}>{result.error}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Box>
  );
}
