// Replay concrete faults against the assertion that owns each Matsui claim.
// Every mutant must build, change dist/, die by assertion, restore byte-for-byte,
// and leave its owning test green again.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const build = [npmCommand, ['run', 'build']];
const vitest = (file, title) => [
  process.execPath,
  [join(root, 'node_modules', 'vitest', 'vitest.mjs'), 'run', file, '--testNamePattern', title],
];

function run([command, args]) {
  return spawnSync(command, args, {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, CI: '1', NO_COLOR: '1' },
  });
}

function pass(command, label) {
  const result = run(command);
  if (result.status !== 0) {
    throw new Error(`${label}\n${result.stdout}\n${result.stderr}`);
  }
  return result;
}

function distHash() {
  const hash = createHash('sha256');
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const pathname = join(directory, entry.name);
      if (entry.isDirectory()) walk(pathname);
      else {
        hash.update(pathname);
        hash.update(readFileSync(pathname));
      }
    }
  };
  walk('dist');
  return hash.digest('hex');
}

const cases = [
  [
    'shared URLs accept an unbounded traffic count',
    'src/state/url.ts',
    'if (TRAFFIC_CHOICES.includes(n as Traffic)) state.traffic = n;',
    'if (Number.isFinite(n)) state.traffic = n;',
    vitest('src/state/url.test.ts', 'rejects traffic values outside the bounded controls'),
  ],
  [
    'the advanced exhibit accepts an unsupported sample count',
    'src/crypto/advanced.ts',
    'if (!ADVANCED_SAMPLE_COUNTS.includes(samples)) {',
    'if (false && !ADVANCED_SAMPLE_COUNTS.includes(samples)) {',
    vitest('src/crypto/advanced.test.ts', 'rejects keys and sample counts outside the advanced controls'),
  ],
  [
    'known-plaintext collection allocates beyond the demo traffic ceiling',
    'src/crypto/attack.ts',
    'if (!Number.isSafeInteger(count) || count < 0 || count > 4096) {',
    'if (!Number.isSafeInteger(count) || count < 0 || false) {',
    vitest('src/crypto/attack.test.ts', 'bounds repeated traffic before allocating its pair array'),
  ],
  [
    'incremental counting accepts an invalid batch size',
    'src/crypto/attack.ts',
    'if (!Number.isSafeInteger(count) || count < 0) {',
    'if (!Number.isSafeInteger(count) || false) {',
    vitest('src/crypto/attack.test.ts', 'rejects invalid incremental batch sizes'),
  ],
  [
    'an unknown runtime S-box name passes through as undefined',
    'src/crypto/sbox.ts',
    'if (!sbox) throw new RangeError(`unknown S-box: ${String(name)}`);',
    'if (false && !sbox) throw new RangeError(`unknown S-box: ${String(name)}`);',
    vitest('src/crypto/sbox.test.ts', 'rejects an unknown runtime S-box name'),
  ],
  [
    'measurement accepts more rounds than the toy key schedule supports',
    'src/crypto/attack.ts',
    'if (!Number.isInteger(cipherRounds) || cipherRounds < 2 || cipherRounds > 4) {',
    'if (!Number.isInteger(cipherRounds) || cipherRounds < 2 || false) {',
    vitest('src/crypto/attack.test.ts', 'rejects measurement requests outside the bounded demo workload'),
  ],
  [
    'measurement accepts a sample count beyond its traffic ceiling',
    'src/crypto/attack.ts',
    'if (sampleCounts.some((samples) => !Number.isSafeInteger(samples) || samples < 1 || samples > sampleLimit)) {',
    'if (sampleCounts.some((samples) => !Number.isSafeInteger(samples) || samples < 1 || false)) {',
    vitest('src/crypto/attack.test.ts', 'rejects measurement requests outside the bounded demo workload'),
  ],
  [
    'measurement accepts more toy keys than the published workload',
    'src/crypto/attack.ts',
    'if (!Number.isSafeInteger(keyCount) || keyCount < 1 || keyCount > 60) {',
    'if (!Number.isSafeInteger(keyCount) || keyCount < 1 || false) {',
    vitest('src/crypto/attack.test.ts', 'rejects measurement requests outside the bounded demo workload'),
  ],
  [
    'a tie is reported as a recovered key nibble',
    'src/crypto/attack.ts',
    'recovered: correctAtTop && winners.length === 1,',
    'recovered: correctAtTop,',
    vitest('src/crypto/attack.test.ts', 'reports a tie rather than claiming a break'),
  ],
  [
    'the second relation is placed in the wrong joint-distribution cells',
    'src/crypto/advanced.ts',
    'joint[(holds[0] ? 2 : 0) + (holds[1] ? 1 : 0)]++;',
    'joint[(holds[0] ? 2 : 0) + (holds[1] ? 0 : 1)]++;',
    vitest('src/crypto/advanced.test.ts', 'keeps the complete joint distribution rather than assuming independence'),
  ],
];

const sourceFiles = [...new Set(cases.map((entry) => entry[1]))];
const dirty = spawnSync('git', ['diff', '--exit-code', '--', ...sourceFiles], {
  cwd: root,
  encoding: 'utf8',
});
if (dirty.status !== 0) {
  throw new Error('Commit the source baseline before mutation checks.');
}

pass(build, 'baseline build');
const baseline = distHash();
const evidence = [];
console.log('baseline: unmutated copy PASSES');
rmSync('mutation-logs', { recursive: true, force: true });
rmSync('mutation-evidence.json', { force: true });
mkdirSync('mutation-logs', { recursive: true });

for (const [name, file, before, after, owner] of cases) {
  pass(owner, `${name}: baseline owner`);
  const original = readFileSync(file, 'utf8');
  if (original.split(before).length !== 2) {
    throw new Error(`${name}: expected exactly one mutation site`);
  }

  let restoredBuild;
  let restoredHash;
  let restoredOwner;
  try {
    writeFileSync(file, original.replace(before, after));
    const sourceDiff = spawnSync('git', ['diff', '--', file], {
      cwd: root,
      encoding: 'utf8',
    }).stdout;
    if (!sourceDiff.trim()) throw new Error(`${name}: source diff is empty`);

    pass(build, `${name}: mutant build`);
    const mutant = distHash();
    if (mutant === baseline) throw new Error(`${name}: production artifact did not move`);

    const result = run(owner);
    const output = result.stdout + result.stderr;
    const logName = name.replaceAll(/[^A-Za-z0-9.-]+/g, '-').replace(/^-|-$/g, '');
    writeFileSync(`mutation-logs/${logName}.log`, `${output.trimEnd()}\n`);
    if (result.status === 0 || !/AssertionError|expected|FAIL|failed/i.test(output)) {
      throw new Error(`${name}: no assertion kill\n${output}`);
    }

    evidence.push({
      name,
      sourceDiff,
      baseline,
      mutant,
      namedTest: owner[1][owner[1].indexOf('--testNamePattern') + 1],
      assertionFailure: true,
      retries: 0,
    });
  } finally {
    writeFileSync(file, original);
    restoredBuild = run(build);
    if (restoredBuild.status === 0) restoredHash = distHash();
    restoredOwner = run(owner);
  }

  if (restoredBuild.status !== 0) {
    throw new Error(`${name}: restore build failed\n${restoredBuild.stdout}\n${restoredBuild.stderr}`);
  }
  if (restoredHash !== baseline) throw new Error(`${name}: restored artifact hash differs`);
  if (restoredOwner.status !== 0) {
    throw new Error(`${name}: restored owner failed\n${restoredOwner.stdout}\n${restoredOwner.stderr}`);
  }
  evidence.at(-1).restoredGreen = true;
  console.log(`${name}: killed; exact artifact restored; owning test green`);
}

writeFileSync('mutation-evidence.json', `${JSON.stringify(evidence, null, 2)}\n`);
console.log(`all ${cases.length} mutation(s) caught`);
