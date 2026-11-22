import { post } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import {
  Box,
  Dialog,
  DialogContent,
  DialogTitle,
  FormControl,
  InputLabel,
  MenuItem,
  Radio,
  RadioGroup,
  Select,
  Stack,
  Typography,
} from '@mui/material';
import { FormControlLabel } from '@mui/material';
import { useSnackbar } from 'notistack';
import { useState } from 'react';
import { errorMessage } from '../common/errors';
import { createExceptionCheck } from '../common/permissions';
import { SetupCheck } from '../common/SetupCheck';
import {
  ClusterSecurityException,
  SecurityException,
} from '../softwarecomposition/SecurityException';
import { ExceptionDialogActions } from './ExceptionDialogActions';
import { AnyException, saveExceptionYaml } from './exceptionYaml';
import { recordChangeByCurrentUser } from './history';
import { ContextBadge, expiryTimestamp, MetadataFields, sanitizeName } from './shared';

export interface GuidedComplianceFormProps {
  controlID: string;
  frameworkName?: string;
  workloadName: string;
  workloadNamespace: string;
  workloadKind: string;
  // the cluster of the workload, the current one by default
  cluster?: string;
  onClose: () => void;
  onCreated?: () => void;
}

type ComplianceScope = 'workload' | 'namespace' | 'kind-cluster' | 'cluster';

export function GuidedComplianceExceptionForm(props: Readonly<GuidedComplianceFormProps>) {
  const { controlID, workloadName, workloadNamespace, workloadKind, cluster, onClose, onCreated } =
    props;
  const { enqueueSnackbar } = useSnackbar();

  const [scope, setScope] = useState<ComplianceScope>('workload');
  const [action, setAction] = useState<'ignore' | 'alert_only'>('ignore');
  const [name, setName] = useState(sanitizeName(`${controlID}-${workloadName}`));
  const [reason, setReason] = useState('');
  const [expiresDate, setExpiresDate] = useState('');

  // A resource without a namespace, such as a ClusterRole, has no namespace for a
  // SecurityException: its exception is a cluster-wide one that names the resource
  const clusterScopedResource = !workloadNamespace;
  const isCluster = clusterScopedResource || scope === 'kind-cluster' || scope === 'cluster';

  const scopeOptions: { value: ComplianceScope; label: string; description: string }[] = [
    ...(clusterScopedResource
      ? [
          {
            value: 'workload' as ComplianceScope,
            label: 'This resource only',
            description: `${workloadKind}/${workloadName}, which has no namespace`,
          },
        ]
      : [
          {
            value: 'workload' as ComplianceScope,
            label: 'This workload only',
            description: `${workloadKind}/${workloadName} in namespace "${workloadNamespace}"`,
          },
          {
            value: 'namespace' as ComplianceScope,
            label: 'All workloads in namespace',
            description: `All workloads in namespace "${workloadNamespace}"`,
          },
        ]),
    {
      value: 'kind-cluster',
      label: `All ${workloadKind} resources cluster-wide`,
      description: `All ${workloadKind} resources across all namespaces`,
    },
    {
      value: 'cluster',
      label: 'All workloads cluster-wide',
      description: 'All workloads across all namespaces',
    },
  ];

  // The exception that Create sends, or undefined after saying what is missing
  const buildException = async (): Promise<AnyException | undefined> => {
    if (!name) {
      enqueueSnackbar('Name is required', { variant: 'error' });
      return undefined;
    }
    const match: Record<string, any> = {};
    if (scope === 'workload') {
      match.resources = [{ kind: workloadKind, name: workloadName }];
    } else if (scope === 'kind-cluster') {
      match.resources = [{ kind: workloadKind }];
    }
    // 'namespace' and 'cluster' scopes: empty match — applies to all workloads in scope

    const spec = {
      ...(reason && { reason }),
      ...(expiresDate && { expiresAt: expiryTimestamp(expiresDate) }),
      match,
      posture: [{ controlID, action }],
    };

    if (isCluster) {
      return recordChangeByCurrentUser<ClusterSecurityException>(
        {
          apiVersion: 'kubescape.io/v1beta1',
          kind: 'ClusterSecurityException',
          metadata: { name },
          spec,
        },
        undefined,
        cluster
      );
    }
    return recordChangeByCurrentUser<SecurityException>(
      {
        apiVersion: 'kubescape.io/v1beta1',
        kind: 'SecurityException',
        metadata: { name, namespace: workloadNamespace },
        spec,
      },
      undefined,
      cluster
    );
  };

  const handleSubmit = async () => {
    const exception = await buildException();
    if (!exception) return;
    const options = cluster ? { cluster } : undefined;
    try {
      await post(
        exception.kind === 'ClusterSecurityException'
          ? '/apis/kubescape.io/v1beta1/clustersecurityexceptions'
          : `/apis/kubescape.io/v1beta1/namespaces/${workloadNamespace}/securityexceptions`,
        exception,
        true,
        options
      );
      enqueueSnackbar('Security exception created', { variant: 'success' });
      onCreated?.();
      onClose();
    } catch (err) {
      enqueueSnackbar(`Failed to create: ${errorMessage(err)}`, { variant: 'error' });
    }
  };

  // the exception that Create would send, for a GitOps repository
  const handleDownload = async () => {
    const exception = await buildException();
    if (exception) await saveExceptionYaml(exception, enqueueSnackbar);
  };

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Create Posture Exception</DialogTitle>
      <DialogContent>
        <SetupCheck features={['exceptions']} />
        <Stack spacing={2} sx={{ mt: 1 }}>
          <MetadataFields
            name={name}
            onNameChange={setName}
            namespace={isCluster ? undefined : workloadNamespace}
            reason={reason}
            onReasonChange={setReason}
            expiresDate={expiresDate}
            onExpiresDateChange={setExpiresDate}
            cluster={cluster}
          />

          <ContextBadge label="Control" value={controlID} />
          <ContextBadge label="Workload" value={`${workloadKind}/${workloadName}`} />
          {cluster && <ContextBadge label="Cluster" value={cluster} />}

          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Exception scope
            </Typography>
            <RadioGroup value={scope} onChange={e => setScope(e.target.value as ComplianceScope)}>
              {scopeOptions.map(opt => (
                <FormControlLabel
                  key={opt.value}
                  value={opt.value}
                  control={<Radio size="small" />}
                  label={
                    <Box>
                      <Typography variant="body2">{opt.label}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {opt.description}
                      </Typography>
                    </Box>
                  }
                  sx={{ alignItems: 'flex-start', mb: 0.5 }}
                />
              ))}
            </RadioGroup>
          </Box>

          <FormControl fullWidth>
            <InputLabel>Action</InputLabel>
            <Select
              value={action}
              label="Action"
              onChange={e => setAction(e.target.value as 'ignore' | 'alert_only')}
            >
              <MenuItem value="ignore">
                <Box>
                  <Typography variant="body2">ignore</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Remove from results and scoring entirely
                  </Typography>
                </Box>
              </MenuItem>
              <MenuItem value="alert_only">
                <Box>
                  <Typography variant="body2">alert_only</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Still fails in scoring, but marked as acknowledged
                  </Typography>
                </Box>
              </MenuItem>
            </Select>
          </FormControl>
        </Stack>
      </DialogContent>
      <ExceptionDialogActions
        onCancel={onClose}
        onDownload={handleDownload}
        onSubmit={handleSubmit}
        submitLabel="Create"
        check={createExceptionCheck(isCluster ? undefined : workloadNamespace)}
        clusters={[cluster]}
      />
    </Dialog>
  );
}
