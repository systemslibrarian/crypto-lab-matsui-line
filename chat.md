# Making Matsui Line a 10/10 Demo

## Executive verdict

This is already an unusually rigorous crypto demo. The math is real, the attack is real, the caveats are honest, the unit suite is strong, and the accessibility spec exercises far more than a token happy path. The remaining gap is not correctness or content. It is **demo direction**.

The best moment, where one real key candidate visibly separates from fifteen wrong guesses, is buried behind several screens of explanation. A 10/10 version should let the learner break the cipher first, then use the LAT, trail, and piling-up exhibits to explain what they just saw.

**Current estimate:** 8.5/10 overall.

| Dimension | Current | Why |
| --- | ---: | --- |
| Cryptographic correctness | 10/10 | Real SPN, counted LAT, exhaustive trail search, real Matsui Algorithm 2 |
| Teaching honesty | 10/10 | Excellent toy-cipher boundaries, measured-vs-predicted caveats, no fake crypto |
| Technical depth | 10/10 | Rewards experts without weakening the mechanism |
| Accessibility engineering | 9.5/10 | Both themes, narrow viewport, dynamic and failure states are exercised |
| First-run clarity | 7/10 | The explanation is good, but the payoff arrives too late |
| Interaction and drama | 7/10 | The result is compelling, but it is already computed and not meaningfully caused by the learner |
| Mobile pacing | 6.5/10 | It fits without body overflow, but the core attack starts far down a very long page |

## Evidence from the current build

- All **84 unit tests pass**, and `npm run build` is clean.
- All **3 production accessibility tests pass**: dark theme, light theme, and the 380 px both-theme sweep report zero WCAG 2.1 A/AA violations.
- At 1440 x 900, the first control begins around **996 px** down and the attack begins around **3352 px** down in a **6421 px** page.
- At 390 x 844, the first control begins around **1651 px** down and the attack begins around **5497 px** down in a **10660 px** page.
- The page contains about **12,500 characters** of visible main-content text across eight large panels.
- The attack ranking is the strongest visual on the page: the winning candidate, actual key, counter bias, and fifteen alternatives are immediately legible.
- The 390 px layout has no page-level horizontal overflow. The problem is journey length, not broken responsiveness.
- `brief.txt` describes an unrelated RSA accumulator. That is a repository-quality defect and a serious trap for the next human or coding agent.

## The highest-impact change

### Lead with the break, then explain it

Move a focused version of **Recover the key** directly below the hero. Make it the first interaction and the visual center of the page.

The learner's opening loop should be:

1. See a hidden four-bit subkey and a stream of real plaintext/ciphertext pairs.
2. Choose how much traffic to collect: 16, 64, or 256 pairs.
3. Press **Run Matsui's attack**.
4. Watch the sixteen real counters resolve in batches until one candidate separates.
5. Reveal the actual nibble and compare it with the attack's pick.
6. Try one-click failure scenarios: **starve the data**, **add one round**, and **use a bad approximation**.

This turns the current result from a report into an experience. After the result, a transition such as **Why did that work?** can lead naturally into the S-box, LAT, and piling-up mechanism.

Do not auto-run the finished attack on load. A pre-populated result removes agency and makes the main button feel redundant. It is fine to precompute the approximation, but the learner should trigger the evidence.

## Recommended page order

1. **Hero** — keep the title and stakes, shorten the description, add one primary action: **Break the toy cipher**.
2. **Attack cockpit** — hidden key, traffic amount, sixteen counters, verdict, and the three failure presets.
3. **How the leak reaches the key** — one connected visual pipeline from S-box bias to key ranking.
4. **Inspect the cipher** — the existing round trace, now serving the question raised by the attack.
5. **Inspect one S-box leak** — selected LAT cell and its sixteen independently computed rows.
6. **Watch the bias compound** — the existing stepper and measured-vs-predicted hull disclosure.
7. **Traffic and success rate** — formula versus real repeated attacks.
8. **Pair-mate comparison and honesty** — keep as expert/reference material near the end.

Add a compact in-page progress strip below the hero, not another header: **Break it / Explain it / Stress it / Limits**. It should scroll to sections and indicate the current section without competing with the managed Crypto Lab top bar.

## Build one connected mechanism visual

The exhibits are individually accurate, but they currently read as separate panels. Connect them with a persistent four-stage story:

```text
12 / 16 S-box agreements
          ↓ real selected LAT cell
trail bias after each round
          ↓ real piling-up result
16 key-guess counters over N pairs
          ↓ real Algorithm 2 ranking
one candidate separates from 1/2
```

Each stage must display values produced by the current configuration. Clicking a stage should jump to or expand its deeper exhibit. The same masks should be highlighted consistently in the trace, LAT, trail, and attack equation so the learner can follow one relation end to end.

Purposeful motion would help here:

- On **Run**, process the real pair set in visible batches and update the actual counters.
- Animate ranking bars only when their real counts change.
- Keep the correct key hidden until counting ends, then reveal whether the attack's pick matches.
- Respect `prefers-reduced-motion` by jumping directly to the final real state.

Do not animate invented packets, random numbers, or decorative “crypto” effects. Every moving quantity should correspond to a computation the code actually performed.

## Make experimentation local and obvious

The controls that change an outcome should live beside that outcome. Today, rounds and S-box live several screens above the attack, while traffic and approximation live inside it.

Use a compact experiment bar in the attack cockpit:

- S-box: `Heys` / `PRESENT`
- Rounds: `2` / `3` / `4`
- Traffic: `16` / `64` / `256` / `1024`
- Target: high / low nibble
- Approximation: verified / strongest unverified / custom

Use segmented controls for short mode sets and retain selects where labels need explanation. Scenario buttons should set several controls at once and say what hypothesis they test, for example **Add one round: does the signal disappear?**

Never leave an old ranking under newly changed controls. Either recompute immediately or replace it with a clear **Configuration changed — run again** state. In particular, changing the traffic slider currently leaves the prior all-codebook verdict visible until the learner presses Run, which can imply that the displayed result used the new traffic amount.

## Reduce reading before doing

The prose is accurate and worth preserving, but too much of it is mandatory before the first action.

- Compress the opening explanation to roughly 80-120 words.
- Keep the five-word glossary collapsed and available beside the first unfamiliar term.
- Move historical context, wrong-key caveats, Parseval, and linear-hull detail behind progressive disclosure near the exhibit that needs it.
- Turn repeated explanations into short captions attached to the changing value.
- Keep the excellent **Real / Not** section, but make it visually quieter and leave it near the end.
- Add linked paper citations in an expert disclosure rather than adding more baseline prose.

The target is not less rigor. It is **less rigor before agency**.

## Give the visual system a stronger focal point

The current dark navy/purple system is polished but visually uniform. Almost every section has the same panel weight, so the eye receives little guidance about what matters most.

- Make the attack cockpit a distinctive, wider work surface rather than another equal card.
- Use the coral alarm color only for a successful attacker outcome, green for a cipher holding, and neutral gray for unresolved candidates.
- Preserve the indigo catalog accent for navigation, focus, and selected masks rather than letting it color every surface.
- Reduce nested borders around secondary data; use spacing, rules, and background bands to establish hierarchy.
- Self-host a deliberate reading face and mono face, such as IBM Plex Sans and IBM Plex Mono, if fleet policy permits. Keep the shared top bar untouched.
- On mobile, show the primary action within the first viewport or immediately after one short hero screen. Large tables can remain horizontally scrollable.

## Make the heavy measurement feel trustworthy

`Measure the real success rate` performs genuine work, which is excellent, but it runs on the main thread. Move repeated attacks into a Web Worker and report real progress such as **137 / 300 attacks complete**.

This gives three benefits:

- the interface remains responsive on slower phones;
- the learner can see that the curve is being measured rather than drawn from a formula;
- cancellation can be offered without abandoning a frozen page.

Use a deterministic seed for a given measurement run and show it in an expert disclosure. Add **Run again with a new seed** for honest variation.

## Make demos and bug reports reproducible

Encode meaningful state in the URL: S-box, rounds, target nibble, pair count, approximation mode, masks, and an optional seed. Add a small **Copy experiment link** action after a result.

Random should remain the default for normal exploration, but `?seed=...` should reproduce the key, pair sample, ranking, and measured curve. This makes classroom presentations reliable and makes surprising outcomes debuggable.

## Testing needed for the final polish

Keep the existing unit and axe suites. Add focused Playwright behavior tests with a deterministic seed:

- the default three-round scenario recovers the expected nibble;
- the four-round scenario communicates failure without marking a wrong key as success;
- low traffic can produce an inconclusive result and is labelled honestly;
- changing configuration invalidates the old result;
- the key remains hidden until the learner asks to reveal or the attack completes;
- copied experiment URLs reproduce the same ranking;
- no body overflow occurs at 320, 390, 768, and 1440 px;
- the primary action is keyboard reachable and visible near the top;
- reduced-motion mode reaches the same final values without animation.

Add two lightweight visual-regression screenshots: the first-run cockpit and one failed-attack state, in dark and light themes. The current accessibility sweep is strong; these tests would cover narrative and state correctness that axe cannot.

## Repository cleanup

Replace or remove the stale accumulator content in `brief.txt` immediately. A 10/10 demo repository cannot have its primary brief specify another product. Make the Matsui scope, accent, references, in-scope exhibits, and non-goals agree across the brief, README, page metadata, and implementation.

Also verify that the README's test count is updated automatically or checked in CI so the otherwise excellent correctness claims do not drift.

## Suggested implementation sequence

### P0 — changes that transform the demo

1. Correct `brief.txt`.
2. Move a focused attack cockpit directly below the hero.
3. Remove the boot-time completed result and make the learner trigger the attack.
4. Put rounds, traffic, and approximation failure presets beside the ranking.
5. Invalidate stale results whenever any outcome-affecting control changes.
6. Compress the opening prose so action arrives within one viewport or one short scroll on mobile.

### P1 — changes that make it memorable

1. Add the real four-stage mechanism visual.
2. Count real pairs in visible batches and animate only computed changes.
3. Add the in-page progress strip and consistent mask highlighting.
4. Move repeated measurement into a Web Worker with progress and cancellation.
5. Strengthen visual hierarchy around the attack cockpit.

### P2 — changes that make it durable

1. Add seeded, URL-shareable experiment state.
2. Add deterministic behavioral and visual-regression tests.
3. Add linked primary-source citations in expert disclosures.
4. Run a five-person comprehension test and revise labels from observed confusion.

## Definition of 10/10

The redesign is done when:

- a first-time learner can run the real attack in under 30 seconds without reading documentation;
- the primary action appears in the first desktop viewport and no later than one short scroll on a 390 x 844 phone;
- the learner can break the attack in three obvious ways without leaving the cockpit;
- no result can remain visible after its controlling configuration has changed;
- the same real masks and values are traceable from S-box evidence through trail bias to key ranking;
- all expensive work stays responsive and reports real progress;
- a shared seeded URL reproduces the same experiment;
- unit, behavior, build, visual, and WCAG checks pass in both themes and at mobile width;
- in a short user test, at least four of five newcomers can explain: **a small S-box bias survives weakly across rounds, and the correct last-round key guess is the one that makes that bias reappear**.

## Do not disturb these strengths

- Do not replace real computation with scripted outcomes.
- Do not weaken the toy-cipher caveat or imply an attack on AES/DES.
- Do not remove measured-vs-predicted disagreement; it is one of the best expert lessons here.
- Do not broaden into multidimensional or zero-correlation cryptanalysis.
- Do not fork or restyle the managed Crypto Lab top bar.
- Do not add more prose to solve a sequencing problem.

The shortest version of the recommendation is: **put the real key-recovery ranking first, let the learner cause it, place the three failure levers next to it, and turn everything below into an explanation of that one event.**