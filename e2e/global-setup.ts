/*
  Fails fast, with what to run, when Headlamp does not run, has not loaded the plugin, or the
  kube context of the tests is missing. Then makes sure Alertmanager holds fresh runtime alerts of
  the intruder pod (e2e/fresh-alerts.sh): they expire an hour after the node-agent sent them, so a
  run some time after the setup starts the intruder again and waits some 6 minutes for its new
  alerts. E2E_SKIP_FRESH_ALERTS=1 skips that, for runs without the runtime alert tests.
*/
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { FullConfig } from '@playwright/test';
import { kubeContext } from './tests/helpers';

/** bash; on Windows the one of Git for Windows, as `bash` there is often WSL's. */
function bash(): string {
  if (process.platform !== 'win32') return 'bash';
  // <Git>/mingw64/libexec/git-core
  const execPath = execFileSync('git', ['--exec-path'], { encoding: 'utf8' }).trim();
  const gitBash = resolve(execPath, '..', '..', '..', 'bin', 'bash.exe');
  if (!existsSync(gitBash)) throw new Error(`Git Bash not found at ${gitBash}`);
  return gitBash;
}

export default async function globalSetup(config: FullConfig) {
  const baseURL = config.projects[0].use.baseURL!;
  let plugins: Array<{ name: string; path: string }>;
  try {
    const response = await fetch(`${baseURL}/plugins`);
    plugins = await response.json();
  } catch (error) {
    throw new Error(
      `Headlamp does not answer at ${baseURL} (${error}). Run e2e/build-plugin.sh and e2e/headlamp.sh first.`
    );
  }
  if (!plugins.some(plugin => plugin.path.endsWith('headlamp_kubescape'))) {
    throw new Error(
      `Headlamp at ${baseURL} has not loaded the plugin: run e2e/build-plugin.sh and e2e/headlamp.sh.`
    );
  }
  try {
    execFileSync('kubectl', ['--context', kubeContext, 'get', 'namespace', 'shop', '-o', 'name'], {
      stdio: 'pipe',
    });
  } catch {
    throw new Error(
      `The kube context ${kubeContext} has no namespace shop: run e2e/setup-kind.sh and e2e/wait-for-scans.sh.`
    );
  }

  if (process.env.E2E_SKIP_FRESH_ALERTS !== '1') {
    const script = join(__dirname, 'fresh-alerts.sh').replaceAll('\\', '/');
    execFileSync(bash(), [script], {
      stdio: 'inherit',
      env: { ...process.env, KUBE_CONTEXT: kubeContext },
    });
  }
}
