/*
  The frameworks whose scores the Compliance page and the Overview show, chosen on the settings
  page: Kubescape's frameworks and the custom frameworks found in the clusters, such as those a
  cluster's GitOps repository provides. The Frameworks menu of the Compliance page changes the
  same setting.
*/
import Autocomplete from '@mui/material/Autocomplete';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import MenuItem from '@mui/material/MenuItem';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import { useEffect, useMemo, useState } from 'react';
import { listCustomObjectConfigMaps } from '../custom-objects/api-queries';
import { defaultFrameworkLabel, isDefaultFramework } from '../framework/customFrameworks';
import { defaultFrameworkNames, useRegoData } from '../rego';

export interface FrameworkChoice {
  activeFrameworks: string[];
  // the framework the Compliance page opens with, '' for all controls
  framework: string;
}

/** Where a custom framework was found, and where it is one of the cluster's defaults. */
export interface CustomFrameworkFound {
  clusters: string[];
  defaultIn: string[];
}

/**
 * The custom frameworks of the clusters, by name. A cluster that cannot be read, such as one that
 * is not running, adds none.
 */
export async function customFrameworkNames(
  clusters: string[]
): Promise<Map<string, CustomFrameworkFound>> {
  const results = await Promise.allSettled(
    clusters.map(async cluster => {
      const configMaps = await listCustomObjectConfigMaps('framework', cluster);
      return configMaps.flatMap(configMap =>
        configMap.data?.name
          ? [{ name: configMap.data.name, isDefault: isDefaultFramework(configMap) }]
          : []
      );
    })
  );
  const byName = new Map<string, CustomFrameworkFound>();
  results.forEach((result, index) => {
    if (result.status !== 'fulfilled') return;
    for (const { name, isDefault } of result.value) {
      const found = byName.get(name) ?? { clusters: [], defaultIn: [] };
      found.clusters.push(clusters[index]);
      if (isDefault) found.defaultIn.push(clusters[index]);
      byName.set(name, found);
    }
  });
  return byName;
}

/** The frameworks shown while none are chosen: the clusters' defaults, else Kubescape's. */
export function shownByDefault(custom: Map<string, CustomFrameworkFound> | null): string[] {
  const clusterDefaults = [...(custom ?? [])]
    .filter(([, found]) => found.defaultIn.length > 0)
    .map(([name]) => name)
    .sort((a, b) => a.localeCompare(b));
  return clusterDefaults.length > 0 ? clusterDefaults : defaultFrameworkNames;
}

/**
 * The choice after the frameworks changed: the Compliance page keeps opening with its framework
 * while it is chosen, else with the first one chosen, or with all controls when none are.
 */
export function chooseFrameworks(names: string[], framework: string | undefined): FrameworkChoice {
  const opened = framework ?? '';
  if (opened === '' || names.includes(opened))
    return { activeFrameworks: names, framework: opened };
  return { activeFrameworks: names, framework: names[0] ?? '' };
}

export function FrameworkSettings(
  props: Readonly<{
    activeFrameworks?: string[];
    framework?: string;
    clusters: string[];
    onChange: (choice: FrameworkChoice) => void;
  }>
) {
  const { activeFrameworks, framework, clusters, onChange } = props;
  const { frameworks } = useRegoData();
  const chosen = activeFrameworks ?? [];
  // where each custom framework was found, null while the clusters are read
  const [custom, setCustom] = useState<Map<string, CustomFrameworkFound> | null>(null);
  const clusterKey = clusters.join(',');

  useEffect(() => {
    if (clusters.length === 0) return;
    let active = true;
    customFrameworkNames(clusters).then(found => active && setCustom(found));
    return () => {
      active = false;
    };
    // clusterKey covers clusters, which is a new array on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clusterKey]);

  // the custom frameworks first, as they are the ones made for these clusters
  const options = useMemo(() => {
    const customNames = [...(custom?.keys() ?? [])].sort((a, b) => a.localeCompare(b));
    const builtIn = frameworks
      .map(found => found.name)
      .filter(name => !custom?.has(name))
      .sort((a, b) => a.localeCompare(b));
    return [...customNames, ...builtIn];
  }, [frameworks, custom]);

  const describe = (name: string) => {
    const found = custom?.get(name);
    if (found) {
      const where = `Custom framework in ${found.clusters.join(', ')}`;
      if (found.defaultIn.length === 0) return where;
      return found.defaultIn.length === found.clusters.length
        ? `${where}, a default there`
        : `${where}, a default in ${found.defaultIn.join(', ')}`;
    }
    if (frameworks.some(framework => framework.name === name)) return 'Kubescape framework';
    return 'Not found in the clusters';
  };
  const defaults = shownByDefault(custom);
  const clusterDefaults = defaults !== defaultFrameworkNames;
  const shown = chosen.length > 0 ? chosen : defaults;

  return (
    <Box display="flex" flexDirection="column" gap={1.5} mt={2}>
      <Typography variant="subtitle1" component="h3">
        Compliance frameworks
      </Typography>
      <Typography variant="body2" color="text.secondary">
        The frameworks whose scores the Compliance page and the Overview show, also chosen with
        Frameworks on the Compliance page. Without a choice, a cluster shows the custom frameworks
        it labels {defaultFrameworkLabel}=true, or else {defaultFrameworkNames.join(', ')}
        {clusterDefaults ? `; your clusters label ${defaults.join(', ')}` : ''}. Custom frameworks
        are found in the Kubescape namespace of each cluster
        {custom === null && clusters.length > 0 ? ' (reading the clusters…)' : ''}; a framework that
        a cluster does not have is left out there.
      </Typography>
      <Autocomplete
        multiple
        freeSolo
        options={options}
        value={chosen}
        onChange={(_event, value) => onChange(chooseFrameworks(value as string[], framework))}
        groupBy={name => (custom?.has(name) ? 'Custom frameworks' : 'Kubescape frameworks')}
        renderOption={(optionProps, name) => (
          <li {...optionProps} key={name}>
            <Box>
              <Typography variant="body2">{name}</Typography>
              <Typography variant="caption" color="text.secondary">
                {describe(name)}
              </Typography>
            </Box>
          </li>
        )}
        renderTags={(value, getTagProps) =>
          value.map((name, index) => (
            <Chip
              {...getTagProps({ index })}
              key={name}
              size="small"
              label={name}
              title={describe(name)}
            />
          ))
        }
        renderInput={params => (
          <TextField
            {...params}
            label="Frameworks to show"
            placeholder={chosen.length > 0 ? '' : `The defaults: ${defaults.join(', ')}`}
          />
        )}
      />
      <Box display="flex" gap={2} alignItems="center" flexWrap="wrap">
        <TextField
          select
          size="small"
          label="Open the Compliance page with"
          value={shown.includes(framework ?? '') ? framework : ''}
          onChange={event => onChange({ activeFrameworks: chosen, framework: event.target.value })}
          sx={{ minWidth: 320 }}
        >
          <MenuItem value="">All controls</MenuItem>
          {shown.map(name => (
            <MenuItem key={name} value={name}>
              {name}
            </MenuItem>
          ))}
        </TextField>
        <Button
          size="small"
          disabled={chosen.length === 0 && !framework}
          onClick={() => onChange({ activeFrameworks: [], framework: '' })}
        >
          Use the defaults
        </Button>
      </Box>
    </Box>
  );
}
