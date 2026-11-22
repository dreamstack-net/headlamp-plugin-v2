import { FormControl, MenuItem, Stack, TextField } from '@mui/material';
import * as yaml from 'js-yaml';
import { useEffect, useState } from 'react';
import { errorMessage } from '../common/errors';
import { ValidatingAdmissionPolicy } from '../types/ValidatingAdmissionPolicy';
import { fetchPluginFile } from './samples';
import { useEvalContext } from './ValidatingAdmissionPolicy';

export function ChoosePolicyButton() {
  const { setValidatingAdmissionPolicy } = useEvalContext();
  const [policies, setKubescapeValidatingAdmissionPolicies] = useState<ValidatingAdmissionPolicy[]>(
    []
  );
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    fetchPluginFile('validating-admission-policies.yaml')
      .then(data => {
        // an empty document, such as after a trailing separator, is no policy
        const loaded = (yaml.loadAll(data) as ValidatingAdmissionPolicy[]).filter(
          policy => policy?.metadata?.name
        );
        if (active) setKubescapeValidatingAdmissionPolicies(loaded);
      })
      .catch(err => {
        if (active) setError(`Unable to read the sample policies: ${errorMessage(err)}`);
      });
    return () => {
      active = false;
    };
  }, []);

  const handleChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    setSelectedValue(event.target.value);
    setValidatingAdmissionPolicy(
      policies?.find(policy => policy.metadata.name === event.target.value)
    );
  };

  const [selectedValue, setSelectedValue] = useState('');

  return (
    <Stack direction="row" spacing={0}>
      <FormControl variant="outlined" sx={{ width: 480 }}>
        <TextField
          select
          value={selectedValue}
          onChange={handleChange}
          label="Choose Sample Policy"
          error={!!error}
          helperText={error}
        >
          {policies?.map((policy, indx) => (
            <MenuItem key={indx} value={policy.metadata.name}>
              {policy.metadata.name}
            </MenuItem>
          ))}
        </TextField>
      </FormControl>
    </Stack>
  );
}
