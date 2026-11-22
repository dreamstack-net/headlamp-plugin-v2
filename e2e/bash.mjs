/*
  Runs scripts of e2e/ with bash, in order, for the npm scripts. On Windows it takes the bash of
  Git for Windows: the `bash` on PATH there is often WSL's, which sees other tools and clusters.

    node e2e/bash.mjs setup-kind.sh build-plugin.sh
*/
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function bash() {
  if (process.platform !== 'win32') return 'bash';
  // <Git>/mingw64/libexec/git-core
  const execPath = execFileSync('git', ['--exec-path'], { encoding: 'utf8' }).trim();
  const gitBash = resolve(execPath, '..', '..', '..', 'bin', 'bash.exe');
  if (!existsSync(gitBash)) {
    throw new Error(`Git Bash not found at ${gitBash}: run the scripts in e2e/ from Git Bash`);
  }
  return gitBash;
}

const here = dirname(fileURLToPath(import.meta.url));
const shell = bash();
for (const script of process.argv.slice(2)) {
  const { status } = spawnSync(shell, [join(here, script).replaceAll('\\', '/')], {
    stdio: 'inherit',
  });
  if (status !== 0) process.exit(status ?? 1);
}
