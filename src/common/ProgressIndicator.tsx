import { Box, Button, CircularProgress, Stack, Typography } from '@mui/material';
import React from 'react';

/**
 * The progress of a read on one line, for a page that already shows what it read so far, such as
 * the workloads while their reports are read. Cancel stops the read like the ProgressIndicator.
 */
export function ProgressLine(
  props: Readonly<{
    continueReading: React.MutableRefObject<boolean>;
    progressMessage: string;
  }>
) {
  const { continueReading, progressMessage } = props;
  return (
    <Stack direction="row" spacing={2} alignItems="center" sx={{ py: 1 }} role="status">
      <CircularProgress size={18} />
      <Typography variant="body2">{progressMessage}</Typography>
      <Button
        size="small"
        variant="outlined"
        onClick={() => {
          continueReading.current = false;
        }}
      >
        Cancel
      </Button>
    </Stack>
  );
}

/**
 * A flag that is always the one of the current read: pages replace the flag of their read when
 * they read again, such as when the selected clusters change, without drawing again, so the
 * Cancel button of the progress would otherwise stop a read that was already replaced.
 */
export function useCurrentReadFlag(
  reading: React.MutableRefObject<React.MutableRefObject<boolean>>
): React.MutableRefObject<boolean> {
  return React.useMemo(
    () => ({
      get current() {
        return reading.current.current;
      },
      set current(value: boolean) {
        reading.current.current = value;
      },
    }),
    [reading]
  );
}

export function ProgressIndicator(
  props: Readonly<{
    continueReading: React.MutableRefObject<boolean>;
    progressMessage: string;
  }>
) {
  const { continueReading, progressMessage } = props;
  const [showProgress, setShowProgress] = React.useState(false);

  // show the progress only after 0.5 sec
  React.useEffect(() => {
    const timer = setTimeout(() => {
      setShowProgress(true);
    }, 500);
    return () => clearTimeout(timer);
  }, []);

  const cancelReading = () => {
    continueReading.current = false;
  };

  return (
    showProgress && (
      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Box sx={{ height: 40 }}>
          <CircularProgress />
        </Box>
        <Box sx={{ m: 2 }}>{progressMessage}</Box>
        <Button onClick={cancelReading} sx={{ m: 2 }} variant="contained">
          Cancel
        </Button>
      </Box>
    )
  );
}
