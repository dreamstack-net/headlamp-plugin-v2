import {
  Box,
  Checkbox,
  FormControl,
  FormControlLabel,
  InputLabel,
  ListItemText,
  MenuItem,
  OutlinedInput,
  Radio,
  RadioGroup,
  Select,
  SelectChangeEvent,
  Stack,
  Typography,
} from '@mui/material';
import React from 'react';
import { kubescapeConfigStore } from '../common/config-store';
import { activeFrameworkNames, FrameWork, useRegoData } from '../rego';
import { configurationScanContext } from './Compliance';
import { frameworkComplianceScore } from './workload-scanning';

export function FrameworkButtons(
  props: Readonly<{
    frameworkName: string;
    customFrameworks: FrameWork[];
    // whether the custom frameworks of the cluster were read
    customFrameworksRead?: boolean;
  }>
) {
  const { frameworkName, customFrameworks, customFrameworksRead } = props;
  const { frameworks } = useRegoData();

  function frameworkChange(event: React.ChangeEvent<HTMLInputElement>, value: string) {
    kubescapeConfigStore.update({ framework: value });
  }

  const selectedFrameworkNames = activeFrameworkNames(
    kubescapeConfigStore.get()?.activeFrameworks,
    customFrameworks
  );

  const labels: JSX.Element[] = [];
  // chosen in the settings, such as the custom frameworks of other clusters
  const missing: string[] = [];

  selectedFrameworkNames
    .toSorted((a, b) => a.localeCompare(b))
    .forEach(name => {
      const framework =
        frameworks.find(fw => fw.name === name) ?? customFrameworks?.find(fw => fw.name === name);
      if (framework) {
        const percentage = configurationScanContext.workloadScans
          ? Math.trunc(frameworkComplianceScore(configurationScanContext.workloadScans, framework))
          : 0;
        labels.push(
          <FormControlLabel
            key={name}
            value={name}
            control={<Radio />}
            label={
              <Stack direction="row" spacing={1}>
                <Box sx={{ color: '#add8e6', fontWeight: 'heavy' }}>{percentage}%</Box>
                <Box>{name}</Box>
              </Stack>
            }
          />
        );
      } else if (frameworks.length > 0 && customFrameworksRead) {
        missing.push(name);
      }
    });

  const frameworkNames: string[] = frameworks
    .map(framework => framework.name)
    .concat(customFrameworks.map(framework => framework.name))
    .sort((a, b) => a.localeCompare(b));

  const handleChange = (event: SelectChangeEvent<typeof selectedFrameworkNames>) => {
    const {
      target: { value },
    } = event;

    const values = typeof value === 'string' ? value.split(',') : value;

    // The framework that the page shows goes with its radio button: unchecked here, the page
    // would stay limited to a framework that can no longer be chosen or left
    const shown = activeFrameworkNames(values, customFrameworks);
    const opened = kubescapeConfigStore.get()?.framework ?? '';
    kubescapeConfigStore.update({
      activeFrameworks: values,
      ...(opened !== '' && !shown.includes(opened) ? { framework: '' } : {}),
    });
  };

  return (
    <>
      <FormControl>
        <RadioGroup
          row
          value={frameworkName}
          name="row-radio-buttons-group"
          onChange={frameworkChange}
        >
          <FormControlLabel value="" control={<Radio />} label="Show all" />
          {labels}
        </RadioGroup>
      </FormControl>
      {missing.length > 0 && (
        <Typography variant="caption" color="text.secondary" sx={{ maxWidth: 260 }}>
          Not in this cluster: {missing.join(', ')}
        </Typography>
      )}
      <FormControl variant="filled" sx={{ m: 1, minWidth: 160 }} size="small">
        <InputLabel id="select-label" sx={{ height: 40 }}>
          Frameworks
        </InputLabel>
        <Select
          labelId="select-label"
          id="simple-select"
          label="Frameworks"
          sx={{ height: 40, width: 160 }}
          value={selectedFrameworkNames}
          multiple
          onChange={handleChange}
          renderValue={() => ''}
          input={<OutlinedInput label="Frameworks" />}
        >
          {frameworkNames.map(frameworkName => (
            <MenuItem key={frameworkName} value={frameworkName}>
              <Checkbox checked={selectedFrameworkNames.includes(frameworkName)} />
              <ListItemText primary={frameworkName} />
            </MenuItem>
          ))}
        </Select>
      </FormControl>
    </>
  );
}
