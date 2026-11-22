/*
  Build a horizontack stack with seperate cells for critical, high, medium, low and unknown.
*/
import { Box, Stack, Tooltip } from '@mui/material';

/** Failed controls per severity, such as spec.severities of a configuration scan summary. */
export interface ControlCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export function getControlsSummary(counts: ControlCounts) {
  const criticalCount = counts.critical;
  const mediumCount = counts.medium;
  const highCount = counts.high;
  const lowCount = counts.low;

  function controlsBox(color: string, severity: string, countScan: number) {
    return (
      <Box
        sx={{
          borderLeft: 2,
          borderTop: 1,
          borderRight: 1,
          borderBottom: 1,
          borderColor: `gray gray gray ${color}`,
          textAlign: 'center',
          width: 100,
        }}
      >
        <Tooltip title={severity}>
          <Box>
            {countScan} {severity}
          </Box>
        </Tooltip>
      </Box>
    );
  }

  return (
    <Stack direction="row" spacing={1}>
      {controlsBox('purple', 'Critical', criticalCount)}
      {controlsBox('red', 'High', highCount)}
      {controlsBox('orange', 'Medium', mediumCount)}
      {controlsBox('yellow', 'Low', lowCount)}
    </Stack>
  );
}
