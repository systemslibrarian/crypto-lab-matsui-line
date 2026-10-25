// Mutation gate for the differential–linear security claims.
//
// Each mutation starts from a committed, clean baseline; builds an exact
// artifact; confirms its OWNING test is green on that artifact; then patches
// one line, rebuilds, and requires the owning test to fail with an assertion
// error (not a timeout, not a crash). The patch is then restored, the rebuild
// is required to hash identically to the baseline, and the owning test must
// be green again. A mutation only counts as killed when every one of those
// steps holds; the unmodified baseline passing is a precondition, not an
// afterthought.
//
// The owning tests are Playwright browser claims, so the mutant is served as
// a real build through `vite preview --outDir <artifact>`: the test cannot
// pass against stale assets the way it can when the config rebuilds `dist/`
// behind the test's back.

import { readFileSync, writeFileSync, readdirSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);
const config = resolve(root, 'playwright.config.ts');

// Serve the exact artifact just hashed. The repo config's own webServer runs
// `npm run build && npm run preview`, which would replace the artifact between
// the hash and the assertion — the exact bug this indirection exists to close.
const PORT = 4665;
const configDir = mkdtempSync(join(tmpdir(), 'matsui-mutations-'));
const testConfig = join(configDir, 'playwright.config.ts');
let artifact;
let buildNumber = 0;
writeFileSync(
  testConfig,
  `
import { defineConfig } from ${JSON.stringify(join(root, 'node_modules/@playwright/test/index.mjs'))};
import base from ${JSON.stringify(config)};
export default defineConfig({
  ...base,
  testDir: ${JSON.stringify(join(root, 'e2e'))},
  webServer: {
    ...base.webServer,
    cwd: ${JSON.stringify(root)},
    command: 'npm run preview -- --port ${PORT} --strictPort --outDir ' + JSON.stringify(process.env.MATSUI_MUTATION_DIST),
    reuseExistingServer: false,
  },
});
`,
);
process.on('exit', () => rmSync(configDir, { recursive: true, force: true }));

const run = (command) =>
  spawnSync(command[0], command[1], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, CI: '1', MATSUI_MUTATION_DIST: artifact },
  });
const pass = (command, label) => {
  const r = run(command);
  if (r.status !== 0) throw Error(`${label}\n${r.stdout}\n${r.stderr}`);
  return r;
};

// A fresh directory per build keeps any prior preview's assets out of this
// artifact. Paths are hashed relative to the artifact so exact restoration is
// testable.
const build = (label) => {
  artifact = join(configDir, `artifact-${buildNumber++}`);
  pass(['npm', ['run', 'build', '--', '--outDir', artifact]], label);
};

const browser = (title) => [
  'npx',
  [
    'playwright',
    'test',
    'e2e/behaviour.spec.ts',
    '--project=chromium',
    '--grep',
    title,
    '--workers=1',
    '--retries=0',
    '--reporter=json',
    '--config',
    testConfig,
  ],
];

const hash = () => {
  const h = createHash('sha256');
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(dir, e.name);
      if (e.isDirectory()) walk(path);
      else {
        h.update(path.slice(artifact.length + 1));
        h.update(readFileSync(path));
      }
    }
  };
  walk(artifact);
  return h.digest('hex');
};

const patch = (file, anchor, replacement) => ({ file, anchor, replacement });
const cases = [
  {
    name: 'DDT entry count doubled',
    patches: [
      patch(
        'src/crypto/difflin.ts',
        'table[din][sbox.table[x] ^ sbox.table[x ^ din]] += 1;',
        'table[din][sbox.table[x] ^ sbox.table[x ^ din]] += 2;',
      ),
    ],
    owner: 'the composition names its pieces',
  },
  {
    name: 'naive heuristic drops one epsilon',
    patches: [
      patch(
        'src/crypto/difflin.ts',
        'return 2 * p * eps * eps;',
        'return 2 * p * eps;',
      ),
    ],
    owner: 'the heuristic stack shows all three numbers',
  },
  {
    name: 'path-aware sum flips sign',
    patches: [
      patch(
        'src/crypto/difflin.ts',
        'total += path.weight * pathPairBias(sbox, design, path.joiningDiff, rhs);',
        'total -= path.weight * pathPairBias(sbox, design, path.joiningDiff, rhs);',
      ),
    ],
    owner: 'the heuristic stack shows all three numbers',
  },
  {
    name: 'path-aware estimate changes the fixed attack equation per path',
    patches: [
      patch(
        'src/crypto/difflin.ts',
        'total += path.weight * pathPairBias(sbox, design, path.joiningDiff, rhs);',
        'total += path.weight * pathPairBias(sbox, design, path.joiningDiff, path.lambdaInDot);',
      ),
    ],
    owner: 'the control measures exactly zero where the heuristic promised signal',
  },
  {
    name: 'last-round peel uses the forward S-box',
    patches: [
      patch(
        'src/crypto/difflin.ts',
        'const v1 = sbox.inverse[(c1 ^ guess) >> 4] << 4 | sbox.inverse[(c1 ^ guess) & 0xf];',
        'const v1 = sbox.table[(c1 ^ guess) >> 4] << 4 | sbox.table[(c1 ^ guess) & 0xf];',
      ),
    ],
    owner: 'the aligned composition recovers the last-round byte',
  },
  {
    name: 'holdout reuses the attack pairs',
    patches: [
      patch(
        'src/crypto/difflin.ts',
        'const holdout = pairs.slice(budget);',
        'const holdout = pairs.slice(0, budget);',
      ),
    ],
    owner: 'the holdout verification confirms the winner',
  },
  {
    name: 'attack budget quietly halved',
    patches: [
      patch(
        'src/crypto/difflin.ts',
        'const attack = pairs.slice(0, budget);',
        'const attack = pairs.slice(0, budget / 2);',
      ),
    ],
    owner: 'the aligned composition recovers the last-round byte',
  },
  {
    name: 'success-rate measurement subtracts its wins',
    patches: [
      patch('src/crypto/difflin.ts', 'wins += 1;', 'wins -= 1;'),
    ],
    owner: 'the measured success rate is a deterministic curve',
  },
  {
    name: 'one-nibble control pretends to rank full-byte guesses',
    patches: [
      patch(
        'src/crypto/difflin.ts',
        'const candidates = subkeyCandidates(design);',
        'const candidates = Array.from({ length: 256 }, (_, guess) => guess);',
      ),
    ],
    owner: 'the control measures exactly zero where the heuristic promised signal',
  },
  {
    name: 'top tie ignores the true key unless it sorts first',
    patches: [
      patch(
        'src/crypto/difflin.ts',
        'const trueAtTop = excess(trueTarget) === excess(winner);',
        'const trueAtTop = winner === trueTarget;',
      ),
    ],
    owner: 'a top tie includes the true byte even when numeric ordering lists another guess first',
  },
  {
    name: 'composition change leaves the prior success curve visible',
    patches: [
      patch(
        'src/main.ts',
        "dlView.measureStarted = false;\n    $('dl-measure-result').replaceChildren();",
        'dlView.measureStarted = false;',
      ),
    ],
    owner: 'changing the composition retires a completed or in-flight success curve',
  },
  {
    name: 'finite-budget control calls sample noise the exact path sum',
    patches: [
      patch(
        'src/ui/difflin.ts',
        '<strong>0</strong>. This selected ${result.attackPairs}-pair run measures',
        '<strong>${signed(result.measuredBias)}</strong>. This selected ${result.attackPairs}-pair run measures',
      ),
    ],
    owner: 'a finite-budget control separates exact cancellation from sample noise',
  },
  {
    name: 'tied hypotheses receive ordinal rather than shared ranks',
    patches: [
      patch(
        'src/ui/difflin.ts',
        'candidate.excess > row.excess',
        'candidate.excess >= row.excess',
      ),
    ],
    owner: 'a top tie includes the true byte even when numeric ordering lists another guess first',
  },
  {
    name: 'stale holdout is rendered as a fresh empty state',
    patches: [
      patch(
        'src/main.ts',
        "renderDlHoldout($('dl-holdout'), shown, dlView.stale);",
        "renderDlHoldout($('dl-holdout'), shown, false);",
      ),
    ],
    owner: 'changing composition settings retires the previous ranking',
  },
  {
    name: 'composition controls leave the URL stale',
    patches: [
      patch(
        'src/main.ts',
        'renderDlPanel();\n  syncUrl();\n}\n\nfunction runDlComposition',
        'renderDlPanel();\n}\n\nfunction runDlComposition',
      ),
    ],
    owner: 'composition controls update the URL and survive reload',
  },
];

const files = [...new Set(cases.flatMap((c) => c.patches.map((p) => p.file)))];
if (run(['git', ['diff', 'HEAD', '--exit-code', '--', ...files]]).status !== 0) {
  throw Error('Commit the source baseline before mutation checks.');
}
// A missing or duplicated anchor is never evidence of a kill.
for (const c of cases) {
  for (const p of c.patches) {
    if (readFileSync(p.file, 'utf8').split(p.anchor).length !== 2) {
      throw Error(`${c.name}: expected exactly one anchor in ${p.file}: ${p.anchor}`);
    }
  }
}

const testResult = (command, slug, phase) => {
  const r = run(command);
  mkdirSync('mutation-logs', { recursive: true });
  writeFileSync(`mutation-logs/${slug}-${phase}.log`, r.stdout + r.stderr);
  let report;
  try {
    report = JSON.parse(r.stdout);
  } catch {
    throw Error(`${slug} ${phase}: missing Playwright JSON report\n${r.stderr}`);
  }
  const specs = [];
  const visit = (suite) => {
    specs.push(...(suite.specs ?? []));
    for (const s of suite.suites ?? []) visit(s);
  };
  for (const suite of report.suites ?? []) visit(suite);
  if (specs.length !== 1 || specs[0].tests.length !== 1 || specs[0].tests[0].results.length !== 1) {
    throw Error(`${slug} ${phase}: expected exactly one named test and zero retries`);
  }
  const result = specs[0].tests[0].results[0];
  return { r, report, result, title: specs[0].title };
};

const green = (command, slug, phase) => {
  const data = testResult(command, slug, phase);
  if (data.r.status !== 0 || data.result.status !== 'passed' || data.report.stats.skipped !== 0) {
    throw Error(`${slug} ${phase}: owning test is not green; see mutation-logs/${slug}-${phase}.log`);
  }
  return data;
};

mkdirSync('mutation-logs', { recursive: true });
build('baseline build');
const baseline = hash();
const evidence = [];
for (const c of cases) {
  const slug = c.name.replaceAll(' ', '-');
  const command = browser(c.owner);
  // Precondition: the owning test is green on the unmodified baseline. A
  // mutation of code whose own test cannot pass is not a kill.
  const unmutated = green(command, slug, 'baseline');
  if (hash() !== baseline) throw Error(`${c.name}: baseline artifact changed between runs`);
  const originals = new Map(c.patches.map((p) => [p.file, readFileSync(p.file, 'utf8')]));
  let record;
  try {
    for (const p of c.patches) {
      const current = readFileSync(p.file, 'utf8');
      if (current.split(p.anchor).length !== 2) {
        throw Error(`${c.name}: anchor changed while applying patches`);
      }
      writeFileSync(p.file, current.replace(p.anchor, p.replacement));
    }
    const diff = pass(['git', ['diff', '--', ...originals.keys()]], 'read mutation diff').stdout;
    if (!diff.trim()) throw Error(`${c.name}: empty diff`);
    build(`${c.name}: mutant must compile`);
    const mutant = hash();
    if (mutant === baseline) throw Error(`${c.name}: bundle hash did not move`);
    const red = testResult(command, slug, 'mutant');
    const failures = (red.result.errors ?? []).map((e) => e.message ?? '').join('\n');
    if (
      red.r.status === 0 ||
      red.result.status !== 'failed' ||
      !/expect\(|AssertionError|Error: expect/.test(failures)
    ) {
      throw Error(`${c.name}: no assertion kill; infrastructure errors and timeouts do not count`);
    }
    if (hash() !== mutant) throw Error(`${c.name}: browser did not retain the mutant build`);
    record = {
      name: c.name,
      patches: c.patches,
      namedTest: unmutated.title,
      baselineGreen: true,
      nonEmptyDiff: true,
      sourceDiff: diff,
      baseline,
      mutant,
      bundleHashMoved: true,
      namedTestRed: true,
      assertionFailure: failures,
      retries: 0,
      skips: red.report.stats.skipped,
    };
  } finally {
    for (const [file, original] of originals) writeFileSync(file, original);
    build(`${c.name}: restore build`);
    if (hash() !== baseline) throw Error(`${c.name}: restored hash differs`);
    green(command, slug, 'restored');
  }
  record.restoredGreen = true;
  record.restoredHash = hash();
  evidence.push(record);
  writeFileSync('mutation-evidence.json', JSON.stringify(evidence, null, 2) + '\n');
  console.log(
    `${c.name}: baseline green; non-empty diff; bundle hash moved; ${record.namedTest} red; restored green`,
  );
}
console.log(`${evidence.length} of ${cases.length} killed; zero retries and skips.`);
