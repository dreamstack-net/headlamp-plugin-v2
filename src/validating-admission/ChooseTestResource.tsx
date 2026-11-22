import {
  Autocomplete,
  FormControl,
  MenuItem,
  Stack,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
} from '@mui/material';
import * as yaml from 'js-yaml';
import { useEffect, useRef, useState } from 'react';
import { getAllowedNamespaces } from '../common/clusterContext';
import { errorMessage } from '../common/errors';
import { fetchResource, listResources, resourceKinds, ResourceRef } from './clusterResources';
import { fetchPluginFile } from './samples';
import { useEvalContext } from './ValidatingAdmissionPolicy';

export function ChooseTestResource() {
  const [source, setSource] = useState<'samples' | 'cluster'>('samples');

  return (
    <Stack direction="row" spacing={1} alignItems="center">
      <ToggleButtonGroup
        size="small"
        exclusive
        value={source}
        onChange={(_, value) => value && setSource(value)}
        aria-label="Test resource source"
      >
        <ToggleButton value="samples">Samples</ToggleButton>
        <ToggleButton value="cluster">From cluster</ToggleButton>
      </ToggleButtonGroup>
      {source === 'samples' ? <ChooseSampleResource /> : <ChooseClusterResource />}
    </Stack>
  );
}

function ChooseSampleResource() {
  const { setResource } = useEvalContext();
  const [testFiles, setTestFiles] = useState<unknown[]>([]);
  const [testFileNames, setTestFileNames] = useState<string[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    // the index names the resources of the test files in their order
    Promise.all([
      fetchPluginFile('vap-test-files.yaml'),
      fetchPluginFile('vap-test-files-index.yaml'),
    ])
      .then(([files, index]) => {
        if (!active) return;
        setTestFiles(yaml.loadAll(files));
        // the index ends with a line break, which is no name
        setTestFileNames(index.split(/\r?\n/).filter(name => name.trim() !== ''));
      })
      .catch(err => {
        if (active) setError(`Unable to read the test resources: ${errorMessage(err)}`);
      });
    return () => {
      active = false;
    };
  }, []);

  const handleChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    setSelectedValue(event.target.value);

    const indx = testFileNames.findIndex(testFile => testFile === event.target.value);
    setResource(testFiles[indx]);
  };

  const [selectedValue, setSelectedValue] = useState('');

  return (
    <FormControl variant="outlined" sx={{ width: 480 }}>
      <TextField
        select
        value={selectedValue}
        onChange={handleChange}
        label="Choose Test Resource"
        error={!!error}
        helperText={error}
      >
        {testFileNames.map((fileName, indx) => (
          <MenuItem key={indx} value={fileName}>
            {fileName}
          </MenuItem>
        ))}
      </TextField>
    </FormControl>
  );
}

function refLabel(ref: ResourceRef) {
  return ref.namespace ? `${ref.namespace}/${ref.name}` : ref.name;
}

/** Picks an object of the current cluster as the test resource. */
function ChooseClusterResource() {
  const { setResource } = useEvalContext();
  const [kind, setKind] = useState('Deployment');
  const [refs, setRefs] = useState<ResourceRef[] | null>(null);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<ResourceRef | null>(null);
  // the read of the resource chosen last; the answers for earlier choices are not used
  const latestRead = useRef(0);

  useEffect(() => {
    let active = true;
    latestRead.current++;
    setRefs(null);
    setSelected(null);
    setError('');
    listResources(kind, getAllowedNamespaces())
      .then(found => active && setRefs(found))
      .catch(err => {
        if (!active) return;
        setRefs([]);
        setError(`Unable to list ${resourceKinds[kind].plural}: ${errorMessage(err)}`);
      });
    return () => {
      active = false;
      latestRead.current++;
    };
  }, [kind]);

  const choose = (ref: ResourceRef | null) => {
    const read = ++latestRead.current;
    setSelected(ref);
    setError('');
    if (!ref) return;
    fetchResource(kind, ref)
      .then(object => {
        if (read === latestRead.current) setResource(object);
      })
      .catch(err => {
        if (read === latestRead.current) {
          setError(`Unable to read ${refLabel(ref)}: ${errorMessage(err)}`);
        }
      });
  };

  return (
    <>
      <TextField
        select
        label="Kind"
        value={kind}
        onChange={event => setKind(event.target.value)}
        sx={{ width: 170 }}
      >
        {Object.keys(resourceKinds).map(name => (
          <MenuItem key={name} value={name}>
            {name}
          </MenuItem>
        ))}
      </TextField>
      <Autocomplete
        sx={{ width: 300 }}
        options={refs ?? []}
        loading={refs === null}
        value={selected}
        onChange={(_, ref) => choose(ref)}
        getOptionLabel={refLabel}
        isOptionEqualToValue={(a, b) => refLabel(a) === refLabel(b)}
        renderInput={params => (
          <TextField
            {...params}
            label={resourceKinds[kind].namespaced ? 'Namespace/name' : 'Name'}
            error={!!error}
            helperText={error}
          />
        )}
      />
    </>
  );
}
