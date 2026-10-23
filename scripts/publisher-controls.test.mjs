import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, URL } from 'node:url';
import process from 'node:process';
import test from 'node:test';

const root = fileURLToPath(new URL('../', import.meta.url));
const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';

// Replace only the external GitHub boundary and exercise the real npm script.
// These controls neither dispatch a workflow nor upload a local build.
function request(exitCode) {
  const directory = mkdtempSync(join(tmpdir(), 'matsui-publish-control-'));
  const gh = join(directory, 'gh');
  writeFileSync(
    gh,
    '#!/usr/bin/env node\nconsole.log(JSON.stringify(process.argv.slice(2)));\nprocess.exit(Number(process.env.PUBLISH_CONTROL_EXIT));\n',
  );
  chmodSync(gh, 0o700);
  try {
    return spawnSync(npmCommand, ['run', 'deploy', '--silent'], {
      cwd: root,
      env: {
        ...process.env,
        PATH: directory + delimiter + process.env.PATH,
        GH_TOKEN: '',
        PUBLISH_CONTROL_EXIT: String(exitCode),
      },
      encoding: 'utf8',
      timeout: 5000,
    });
  } finally {
    rmSync(directory, { recursive: true });
  }
}

test('publishing requests the existing gated main workflow', () => {
  const result = request(0);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout.trim()), [
    'workflow',
    'run',
    'deploy.yml',
    '--repo',
    'systemslibrarian/crypto-lab-matsui-line',
    '--ref',
    'main',
  ]);
});

test('a rejected publishing request retains its failing exit status', () => {
  const result = request(73);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 73);
});
