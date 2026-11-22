/*
  The samples of the playground that the plugin ships in public/: the policies of the Kubescape
  CEL admission library, their parameters and the test resources.
*/
import * as yaml from 'js-yaml';
import { useEffect, useState } from 'react';
import { errorMessage } from '../common/errors';
import { getKubescapePluginUrl } from '../common/PluginHelper';

/** The text of a file of the plugin, or an error that names the file. */
export async function fetchPluginFile(name: string): Promise<string> {
  const response = await fetch(`${await getKubescapePluginUrl()}/${name}`);
  if (!response.ok) {
    throw new Error(`${name} answered ${response.status} ${response.statusText}`.trim());
  }
  return response.text();
}

/**
 * The sample parameters of a policy that reads parameters, or null for a policy that does not.
 * An answer for a policy chosen before is not used.
 */
export function useSampleParams(policy: { spec?: { paramKind?: { apiVersion?: string } } } | null) {
  const [params, setParams] = useState<unknown>(null);
  const [error, setError] = useState('');
  const needsParams = !!policy?.spec?.paramKind?.apiVersion;

  useEffect(() => {
    let active = true;
    setParams(null);
    setError('');
    if (needsParams) {
      fetchPluginFile('basic-control-configuration.yaml')
        .then(data => {
          if (active) setParams(yaml.load(data) ?? null);
        })
        .catch(err => {
          if (active) setError(`Unable to read the sample parameters: ${errorMessage(err)}`);
        });
    }
    return () => {
      active = false;
    };
  }, [policy, needsParams]);

  return { params, error };
}
