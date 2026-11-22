/*
  Relearning the behaviour of a workload from its profile: restarting the workload so its new
  pods are learned from their start, and deleting the profiles it no longer uses.
*/
import { Icon } from '@iconify/react';
import {
  Alert,
  AlertTitle,
  Box,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  IconButton,
  Stack,
  Tooltip,
  Typography,
} from '@mui/material';
import { useSnackbar } from 'notistack';
import { ReactNode, useEffect, useRef, useState } from 'react';
import { errorMessage } from '../common/errors';
import { Permitted, useCanI } from '../common/permissions';
import type { ContainerProfile } from '../softwarecomposition/ContainerProfile';
import type { ProfileResource } from '../softwarecomposition/profileApi';
import {
  deleteProfiles,
  deleteProfilesCheck,
  fetchWorkload,
  fetchWorkloadProfiles,
  isPartial,
  restartableResources,
  restartCheck,
  RestartImpact,
  restartImpact,
  restartWorkload,
  workloadOfProfile,
} from './relearn';

function Choice(
  props: Readonly<{
    checked: boolean;
    disabled?: boolean;
    onChange: (checked: boolean) => void;
    label: string;
    description: ReactNode;
  }>
) {
  const { checked, disabled, onChange, label, description } = props;
  return (
    <FormControlLabel
      control={
        <Checkbox
          size="small"
          checked={checked}
          disabled={disabled}
          onChange={(_, value) => onChange(value)}
        />
      }
      label={
        <Box>
          <Typography variant="body2">{label}</Typography>
          <Typography variant="caption" color="text.secondary">
            {description}
          </Typography>
        </Box>
      }
      sx={{ alignItems: 'flex-start' }}
    />
  );
}

function plural(count: number, word: string) {
  return `${count} ${word}${count === 1 ? '' : 's'}`;
}

/** Asks how to relearn the workload of a profile, and does it. */
export function RelearnDialog(
  props: Readonly<{
    profile: ContainerProfile;
    source: ProfileResource;
    onClose: () => void;
    onDone: () => void;
  }>
) {
  const { profile, source, onClose, onDone } = props;
  const workload = workloadOfProfile(profile)!;
  const restartable = workload.kind in restartableResources;
  const { enqueueSnackbar } = useSnackbar();
  const [profiles, setProfiles] = useState<ContainerProfile[] | null>(null);
  const [restart, setRestart] = useState(restartable);
  // deleting the profiles is proposed when a restart replaces the pods that they belong to
  const [cleanup, setCleanup] = useState(restartable);
  // whether the user chose that themselves, which reading the workload then leaves as it is
  const cleanupChosen = useRef(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // whether the restart is done, so that trying again after deleting the profiles failed does
  // not roll the workload out a second time
  const [restarted, setRestarted] = useState(false);
  const canRestart = useCanI(restartCheck(workload), workload.cluster);
  // one check, or two for the halves of a profile on older Storage releases
  const deleteChecks = deleteProfilesCheck(workload, source);
  const canDeleteFirst = useCanI(deleteChecks[0], workload.cluster);
  const canDeleteSecond = useCanI(deleteChecks[1] ?? null, workload.cluster);
  const canDelete = canDeleteFirst === false || canDeleteSecond === false ? false : canDeleteFirst;
  // how the restart replaces the pods, once the workload is read
  const [impact, setImpact] = useState<RestartImpact | null>(null);

  useEffect(() => {
    let active = true;
    fetchWorkloadProfiles(workload, source)
      // without the list, at least the profile at hand is deleted
      .catch(() => [profile])
      .then(found => {
        if (active) setProfiles(found.length > 0 ? found : [profile]);
      });
    if (restartable) {
      fetchWorkload(workload)
        .catch(() => undefined)
        .then(object => {
          if (!active) return;
          const read = restartImpact(workload.kind, object);
          setImpact(read);
          // pods that the restart leaves running still use their profiles, so deleting those is
          // no longer proposed; a workload without pods has none that would lose its profile
          if (read.leavesPodsRunning && !cleanupChosen.current) setCleanup(false);
        });
    }
    return () => {
      active = false;
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // the restart that was chosen, done or still to do
  const restarting = restarted || (restart && restartable && canRestart !== false);
  const doRestart = restarting && !restarted;
  const doCleanup = cleanup && canDelete !== false && !!profiles;
  // whether new pods replace those of the profiles; otherwise the running pods keep running
  // without a profile, as Kubescape only learns a container from its start
  const replacesPods = restarting && impact?.replacesPods !== false;
  // what the button does is not known until the workload and the profiles to delete are read
  const reading = (doRestart && !impact) || (cleanup && canDelete !== false && !profiles);
  const subject = `${workload.kind} ${workload.name}`;

  const relearn = async () => {
    setBusy(true);
    setError(null);
    const done: string[] = [];
    try {
      if (doRestart) {
        await restartWorkload(workload);
        setRestarted(true);
        done.push(`Restarted ${subject}: its new pods are learned from their start.`);
      }
      // the profiles were read before the restart, so the one of the new pods stays
      if (doCleanup) {
        await deleteProfiles(profiles!, source, workload.cluster);
        done.push(`Deleted ${plural(profiles!.length, 'profile')} of ${subject}.`);
      }
      enqueueSnackbar(done.join(' '), { variant: 'success' });
      onDone();
    } catch (err) {
      setError(`${done.length > 0 ? `${done.join(' ')} ` : ''}Then failed: ${errorMessage(err)}`);
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth aria-labelledby="relearn-title">
      <DialogTitle id="relearn-title">Relearn {subject}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Typography variant="body2">
            Kubescape learns how each container behaves during the learning period after the
            container starts, 24 hours unless the node-agent is set otherwise. The anomaly rules
            alert on what it did not learn. A pod label <code>kubescape.io/max-sniffing-time</code>,
            such as <code>2h</code>, sets the learning period of a workload.
          </Typography>
          {isPartial(profile) && (
            <Alert severity="info">
              Kubescape began to watch this container after it had started, so it did not learn the
              start. A restart lets it learn the whole run.
            </Alert>
          )}

          {restartable ? (
            <Permitted check={restartCheck(workload)} cluster={workload.cluster}>
              {allowed => (
                <Choice
                  checked={restarted || (restart && allowed)}
                  disabled={!allowed || restarted}
                  onChange={setRestart}
                  label={
                    restarted
                      ? `Restarted the ${workload.kind}`
                      : `Restart the ${workload.kind} now`
                  }
                  description="Replaces every pod of the workload, as kubectl rollout restart does. The new pods get a new profile that is learned from their start."
                />
              )}
            </Permitted>
          ) : (
            <Typography variant="body2" color="text.secondary">
              {workload.kind === 'Pod'
                ? 'A pod without a controller cannot be restarted here: delete it and create it again to relearn it.'
                : `Every run of a ${workload.kind} is learned from its start, so the next run learns again.`}
            </Typography>
          )}

          <Permitted check={deleteChecks} cluster={workload.cluster}>
            {allowed => (
              <Choice
                checked={cleanup && allowed}
                disabled={!allowed || !profiles}
                onChange={checked => {
                  cleanupChosen.current = true;
                  setCleanup(checked);
                }}
                label={
                  profiles
                    ? `Delete the ${plural(profiles.length, 'recorded profile')} of this workload`
                    : 'Delete the recorded profiles of this workload'
                }
                description={
                  restartable
                    ? 'They belong to the pods that the restart replaces, or to earlier versions of the workload.'
                    : 'They belong to earlier runs.'
                }
              />
            )}
          </Permitted>

          {doRestart && (
            <Alert severity={impact?.severity ?? 'warning'}>
              <AlertTitle>
                This restarts {subject}
                {workload.cluster ? ` in cluster ${workload.cluster}` : ''}
              </AlertTitle>
              {replacesPods &&
                'Every pod of the workload is replaced, which can interrupt what it serves. '}
              {impact ? impact.text : 'Reading the workload…'}
              {replacesPods && (
                <Box sx={{ mt: 1 }}>
                  Until the new profile is learned, the rules that compare with the profile do not
                  alert on this workload.
                </Box>
              )}
            </Alert>
          )}
          {doCleanup && !replacesPods && (
            <Alert severity="warning">
              The pods that keep running lose their profile and are not learned again until they
              start anew: until then the rules that compare with a profile do not alert on them.
            </Alert>
          )}
          {error && <Alert severity="error">{error}</Alert>}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          color={doRestart ? 'error' : 'primary'}
          disabled={busy || reading || (!doRestart && !doCleanup)}
          onClick={relearn}
        >
          {doRestart
            ? 'Restart and relearn'
            : restarted
            ? 'Retry deleting profiles'
            : 'Delete profiles'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** A button that opens the relearn dialog, as an icon in a table or as a page action. */
export function RelearnButton(
  props: Readonly<{
    profile: ContainerProfile;
    source: ProfileResource;
    onDone: () => void;
    text?: boolean;
  }>
) {
  const { profile, source, onDone, text } = props;
  const [open, setOpen] = useState(false);
  if (!workloadOfProfile(profile)) return null;

  return (
    <>
      {text ? (
        <Button variant="outlined" onClick={() => setOpen(true)}>
          Relearn
        </Button>
      ) : (
        <Tooltip title="Relearn">
          <IconButton size="small" aria-label="Relearn" onClick={() => setOpen(true)}>
            <Icon icon="mdi:school-outline" />
          </IconButton>
        </Tooltip>
      )}
      {open && (
        <RelearnDialog
          profile={profile}
          source={source}
          onClose={() => setOpen(false)}
          onDone={() => {
            setOpen(false);
            onDone();
          }}
        />
      )}
    </>
  );
}
