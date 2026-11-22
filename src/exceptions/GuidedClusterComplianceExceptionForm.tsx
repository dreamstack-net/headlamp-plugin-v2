import {
  Box,
  Dialog,
  DialogContent,
  DialogTitle,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Typography,
} from '@mui/material';
import { useSnackbar } from 'notistack';
import { useState } from 'react';
import { createExceptionCheck } from '../common/permissions';
import { SetupCheck } from '../common/SetupCheck';
import { ClusterSecurityException } from '../softwarecomposition/SecurityException';
import { ExceptionDialogActions } from './ExceptionDialogActions';
import { saveExceptionYaml } from './exceptionYaml';
import {
  createClusterException,
  createdInClustersMessage,
  recordChangeByCurrentUser,
} from './history';
import { ContextBadge, expiryTimestamp, MetadataFields, sanitizeName } from './shared';

export interface GuidedClusterComplianceExceptionFormProps {
  controlID: string;
  // the clusters whose results the page shows, the current one by default
  clusters?: string[];
  onClose: () => void;
  onCreated?: () => void;
}

export function GuidedClusterComplianceExceptionForm(
  props: Readonly<GuidedClusterComplianceExceptionFormProps>
) {
  const { controlID, clusters, onClose, onCreated } = props;
  const { enqueueSnackbar } = useSnackbar();

  const [action, setAction] = useState<'ignore' | 'alert_only'>('ignore');
  const [name, setName] = useState(sanitizeName(`${controlID}-cluster`));
  const [reason, setReason] = useState('');
  const [expiresDate, setExpiresDate] = useState('');

  // The exception that Create sends to each cluster, or undefined after saying what is missing
  const buildException = (): ClusterSecurityException | undefined => {
    if (!name) {
      enqueueSnackbar('Name is required', { variant: 'error' });
      return undefined;
    }
    return {
      apiVersion: 'kubescape.io/v1beta1',
      kind: 'ClusterSecurityException',
      metadata: { name },
      spec: {
        ...(reason && { reason }),
        ...(expiresDate && { expiresAt: expiryTimestamp(expiresDate) }),
        match: {},
        posture: [{ controlID, action }],
      },
    };
  };

  const handleSubmit = async () => {
    const exception = buildException();
    if (!exception) return;
    const result = await createClusterException(exception, clusters);
    const { message, variant } = createdInClustersMessage('Security exception', result);
    enqueueSnackbar(message, { variant });
    if (result.created.length > 0) {
      onCreated?.();
      onClose();
    }
  };

  // the exception that Create would send, with the user of the first cluster as its author
  const handleDownload = async () => {
    const exception = buildException();
    if (!exception) return;
    await saveExceptionYaml(
      await recordChangeByCurrentUser(exception, undefined, clusters?.[0]),
      enqueueSnackbar
    );
  };

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Exclude Control Cluster-wide</DialogTitle>
      <DialogContent>
        <SetupCheck features={['exceptions']} />
        <Stack spacing={2} sx={{ mt: 1 }}>
          <MetadataFields
            name={name}
            onNameChange={setName}
            reason={reason}
            onReasonChange={setReason}
            expiresDate={expiresDate}
            onExpiresDateChange={setExpiresDate}
            cluster={clusters?.[0]}
          />

          <ContextBadge label="Control" value={controlID} />
          <ContextBadge label="Scope" value="All namespaces — cluster-wide" />
          {clusters && clusters.length > 1 && (
            <ContextBadge label="Clusters" value={clusters.join(', ')} />
          )}

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
        check={createExceptionCheck()}
        clusters={clusters}
      />
    </Dialog>
  );
}
