# crypto-lab-matsui-line

## What It Is

**Linear cryptanalysis** is a known-plaintext attack on block ciphers, published by Mitsuru Matsui in 1993 and used by him in 1994 for the first experimental break of full DES. It works by finding linear approximations — statements of the form "this XOR of plaintext bits equals that XOR of round-input bits" — that hold slightly more often than half the time because the cipher's S-boxes are not perfectly balanced. The **piling-up lemma** describes how those small biases compound across rounds, and **Matsui's Algorithm 2** turns the surviving bias into key bits: guess part of the final subkey, undo the last round under each guess, and see which guess makes the bias appear.

This demo implements the attack against the same toy 4-round SPN that [crypto-lab-biham-lens](https://systemslibrarian.github.io/crypto-lab-biham-lens/) attacks with differentials — 8-bit block, 16-bit key, a 4-bit S-box on each nibble, and a bit permutation for diffusion. Every ciphertext on the page comes out of that real cipher, every bias is counted rather than asserted, and the trail search is exhaustive over the 8-bit mask space rather than a heuristic.

**This is not production cryptography.** An 8-bit block has 256 plaintexts; the entire codebook fits in a browser tab, and the cipher is broken by definition. It exists so the attack is visible at a scale you can watch. Breaking it proves nothing about AES or DES — it demonstrates the mechanism that forced their designs.

The security model on display is deliberately generous to the attacker in one way and strict in another: they see plaintext/ciphertext pairs they did not choose (weaker access than differential cryptanalysis needs), and they never touch the key — the demo checks their answer against the real key only after the attack has finished.

## Exhibits

The page opens on the attack itself. Everything below it exists to explain the thing you just watched happen.

1. **Break the toy cipher** — the cockpit. A hidden four-bit subkey, sixteen counters, and a Run button. Press it and the pairs are counted in front of you: the counters move because the numbers moved, and a partial count is exactly what an attacker with that much traffic would have. The key stays hidden until the count finishes. Four one-click scenarios try to break the attack — **starve it** (16 pairs), **add a round** (the leak shrinks below the noise), **bad relation** (an approximation with provably zero bias), **reset**. Changing any control that affects the outcome retires the result rather than leaving it under settings that did not produce it. *Copy experiment link* pins the key and seed so a surprising result is reproducible by whoever you send it to.
2. **Why did that work?** — one connected chain from a single S-box's imbalance to one key candidate separating, each link showing the value your current settings actually produce, each link a link to the exhibit behind it.
3. **Inspect the cipher** — send a plaintext through and watch every intermediate state in binary. The state the attack aims at is marked.
4. **Inspect one S-box leak** — the full 16×16 linear approximation table. Each cell is a button; selecting one shows all 16 inputs with both sides of the approximation computed independently and compared, so the table's number is visibly the sum of that column rather than a claim. Cells the current trail rides on are ringed.
5. **Watch the bias compound** — step through the trail one round at a time and watch the piling-up lemma shrink the bias, in both its bias form (ε = 2ⁿ⁻¹ ∏ εᵢ) and its correlation form, plus what each extra round costs in traffic. A disclosure panel then measures the true bias by running the real cipher over all 256 plaintexts for ten different keys — which is where the **linear hull effect** shows up: over two rounds the lemma is exact (every key gives |ε| = 1/8 on the nose; only the sign moves), while over three rounds the measured bias scatters with the key. Take the strongest three-round trail the lemma can find (the *strongest, unverified* setting in exhibit 1) and its true bias ranges from 5/64 down to *exactly zero* across ten keys, while the prediction sits unmoved at 27/512.
6. **Look at more than one relation** — select one of three fixed toy keys and 16, 64 or all 256 distinct plaintexts. The lab counts two mask relations on the same traffic and displays all four joint outcomes. A third mask pair has no nonzero two-round trail and therefore zero full-codebook correlation for every key; a short sample can still look biased. This is a bounded observation, not a multidimensional key-recovery attack.
7. **How much traffic do you need?** — Matsui's inverse-square rule, with the sample count for a target success rate, next to the **measured** success rate of the attack run end to end over 60 random keys per data size. The original measurement remains 300 complete attacks. A second comparison runs the same attack on the same 60 toy keys under repeated draws and distinct random plaintexts at equal budgets (16–256 pairs). It shows the number of unique inputs, an interval for the measured across-key success fraction, and the finite-population variance factor for one relation. Both measurements run in a cancellable Web Worker.
8. **The pair-mate attack** — differential versus linear across seven properties, with the honest note about how far each reaches on a block this small.
9. **Weld the two attacks together** — a fixed differential–linear composition on the 3-round Heys-S-box form of the shared toy cipher. Chosen pairs with difference `0x0B` drive round 1, a biased parity reads round 2, and the join is the explicit state entering round 2. The aligned construction's output mask spans both nibbles, so it peels and ranks all 256 final-whitening-byte hypotheses by absolute bias. Its p-weighted Biham–Dunkelman–Keller heuristic is 9/64, its signed DDT-row estimate is 9/32, and the full-codebook measurement is 1/4 or 5/16 depending on the key; the page computes the current key's value rather than asserting one universal result. The control's p-weighted heuristic is 1/16, but paths evaluated against the attack's one fixed right-hand side contribute with opposite signs: the corrected path sum and full-codebook bias are both zero. A partial-budget run can still deviate through finite-sample noise. Because that control mask observes only the high nibble, it honestly ranks 16 high-nibble hypotheses rather than pretending to recover a byte. Fresh held-out pairs independently check the aligned winner. A deterministic 512-key measurement puts the true byte in the top equivalence class for 31.3%, 66.8%, 90.2%, 99.8% and 100% of keys at 16, 32, 64, 96 and 128 pairs; ties count only as partial recovery. The stride disperses this reproducible bounded sample across the key space but is not a random population estimate. The exhibit makes no claim that its selected masks are optimal for four rounds or that it attacks the full toy cipher.
10. **Limits** — what is real here and what this does not prove.

## When to Use It

- **Evaluating a new block cipher or S-box.** Computing the LAT and searching for multi-round trails is one of the first things a designer does; a maximum LAT entry that is too large is a disqualifying result.
- **Justifying round counts.** The inverse-square data requirement is what turns "one more round" into "four times the traffic", and it is the argument behind the round counts in AES, PRESENT, and Serpent.
- **Teaching why non-linearity matters.** The S-box is the only non-linear component; the attack is a demonstration of what happens to the parts of a cipher that are linear.
- **Analysing legacy or bespoke ciphers.** Ciphers designed before 1993, or designed without cryptanalytic review, frequently have exploitable linear approximations.
- **When NOT to use it:** do not reach for linear cryptanalysis against a modern standardised cipher and expect a result — AES, ChaCha20 and their peers were designed specifically to make the required data exceed the number of blocks the mode will ever encrypt. And **do NOT treat the toy SPN here as a cipher**: it is a teaching target, not cryptography.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-matsui-line](https://systemslibrarian.github.io/crypto-lab-matsui-line/)**

Press **Run Matsui's attack** and watch sixteen counters resolve on real traffic until one candidate separates — then find out it was the key. From there: take the data away and watch it stop working, add the fourth round and watch the ranking dissolve into noise, swap the S-box, invent your own masks, or press *Measure the real success rate* and get a curve produced by running the attack 300 times rather than by evaluating a formula.

Nothing is precomputed for show. Every counter that moves was counted, including the partial ones.

## What Can Go Wrong

Real failure modes — in the attack, and in ciphers that must resist it.

- **Trusting the piling-up lemma as if it were a measurement.** The lemma assumes rounds are independent. Where several trails join the same pair of masks, they add or cancel depending on the key — the linear hull effect. This demo shows the predicted bias and the measured bias side by side; over three rounds they diverge badly, and for at least one key in ten the cancellation is total: the true bias is zero and the approximation is worthless against that key at any data volume.
- **Trusting the wrong-key randomisation hypothesis.** Algorithm 2 assumes a wrong guess produces an unbiased counter. On a small block it does not: exhaustive screening here finds approximations with a textbook-perfect 1/8 bias that still never name the key, because the correct candidate stays permanently tied with an impostor. A strong trail is a necessary but not sufficient condition for key recovery, and the demo screens every candidate against the real cipher rather than assuming.
- **Choosing an S-box on differential properties alone.** The two attacks are not the same attack. On this toy, the Heys S-box protects one nibble of the final subkey from every linear approximation we could find, while the PRESENT S-box — the stronger of the two against differentials — leaves both nibbles recoverable. Designers must clear both bars, plus several more.
- **Under-counting the data requirement.** The familiar 1/ε² figure describes one counter reading correctly. Algorithm 2 needs one counter to out-lean fifteen rivals, which costs substantially more; here the measured success rate lags the formula's prediction at every data size.
- **Confusing a trail with a whole approximation.** A fixed round-key XOR can change the sign of an individual trail's contribution but not its magnitude. A full linear approximation sums many trails with key-dependent signs, so their contributions can reinforce or cancel to zero. In this toy's three-round hull, input mask `0x01` and output mask `0x50` match 128/256 plaintexts for master key `0x0000` (zero bias), but 130/256 for key `0x1234` (bias 1/128). See [*On Linear Hulls and Trails* (2016)](https://eprint.iacr.org/2016/088) and Beyne and Rijmen, [*Linear Cryptanalysis* (2025), ch. 2](https://www.cambridge.org/core/books/linear-cryptanalysis/DFB9A56FA0EC663A9AC3D99F9D241461).
- **Treating repeated inputs as new evidence.** With an 8-bit block, repeated random traffic revisits plaintexts. Sampling distinct random plaintexts increases coverage but does not let the attacker choose them. For a fixed key and relation with match fraction *p*, the count variance for *N* distinct plaintexts is `N p(1−p) (256−N)/255`, versus `N p(1−p)` with replacement. At *N* = 256 the count has no sampling variance. The panel's Wilson intervals instead describe uncertainty in the observed success proportion over 60 random toy keys; they are neither per-key guarantees nor security proofs. See Beyne and Rijmen, [*Linear Cryptanalysis* (2025), ch. 4](https://www.cambridge.org/core/books/abs/linear-cryptanalysis/statistics-of-linear-cryptanalysis/4233F6B7EFEC3E49BDE1958049BAA16C).
- **Trusting the differential–linear heuristic off the designated path.** Langford and Hellman's original probability-one composition gives bias `2·ε²`; the published Biham–Dunkelman–Keller enhancement gives `2·p·ε²` by assuming pairs outside the prefix condition have random output parities. With `λin = 0x02`, every path in the chosen DDT row has the designated right-hand side, so signed path contributions reinforce: 9/64 becomes a path-aware 9/32, while the real key-dependent measurement is 1/4 or 5/16 because joining values within a path are not a uniform independent population. With `λin = 0x04`, evaluating every path against the attack's *fixed* designated-path equation gives contributions `[0, +1/2, 0, −1/2, 0]`; their weighted sum and the real full-codebook measurement are zero. The control's `λout = 0xC0` sees only the high key nibble, so its no-signal experiment ranks 16 honest hypotheses and makes no byte-recovery claim. See Langford and Hellman, [*Differential–Linear Cryptanalysis* (CRYPTO '94)](https://doi.org/10.1007/3-540-48658-5_3), Biham, Dunkelman and Keller, [*Enhancing Differential-Linear Cryptanalysis* (ASIACRYPT 2002)](https://doi.org/10.1007/3-540-36178-2_16), and Lu, [*New Methodologies for Differential-Linear Cryptanalysis and Its Extensions* §3.1](https://eprint.iacr.org/2010/025).
- **Confusing a structural zero with a sample count.** The new two-mask panel distinguishes a pair with no nonzero trail (zero correlation over all 256 plaintexts for every key) from an ordinary relation that happens to cancel under one key or look balanced in a finite sample. It shows the four joint outcomes instead of assuming two mask counts are independent. This is a small window into [multiple linear cryptanalysis](https://www.cambridge.org/core/books/linear-cryptanalysis/multiple-linear-cryptanalysis/0E7438A0DE3F39BF647B0F2708756D40) and [zero-correlation analysis](https://www.cambridge.org/core/books/abs/linear-cryptanalysis/zerocorrelation-approximations/2720458FF754C2EBDF691CDFC0FAE59F), not either complete attack.

## Real-World Usage

- **DES (FIPS 46, 1977).** Matsui broke the full 16-round cipher with 2⁴³ known plaintexts and, in 1994, actually executed it — 50 days on 12 workstations, the first experimental break of DES. Linear cryptanalysis, unlike the differential attack the design had been secretly hardened against, was not anticipated by DES's designers.
- **AES / Rijndael (FIPS 197, 2001).** The AES S-box was chosen for a maximum linear correlation of 2⁻³, and the wide-trail design strategy bounds the number of active S-boxes per four rounds. Both exist to make linear approximations decay fast enough that no useful trail crosses ten rounds.
- **PRESENT (CHES 2007).** The S-box shipped in this demo. Bogdanov et al. selected it under explicit criteria including a maximum linear bias of 4/16, and the paper's security argument bounds the number of active S-boxes in any linear trail.
- **Serpent (AES finalist, 1998).** Co-designed by Eli Biham, of the pair-mate attack. Its 32 rounds were chosen to give a large margin against both differential and linear cryptanalysis simultaneously.
- **Cipher standardisation generally.** Since 1994, resistance to linear cryptanalysis has been a threshold requirement rather than a feature: a submission that cannot bound its best linear trail does not get evaluated further.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-matsui-line
cd crypto-lab-matsui-line
npm install
npm run dev
```

`npm test` runs the unit suite; `npm run build && npm run test:a11y` runs the production build through the browser and accessibility gate. `npm run test:mutations` proves the differential–linear claim tests reject fifteen targeted source mutations.

## Related Demos

- [crypto-lab-biham-lens](https://systemslibrarian.github.io/crypto-lab-biham-lens/) — differential cryptanalysis of the same toy SPN. The pair-mate attack, and the direct comparison this demo is built against.
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — the cipher whose S-box was chosen to survive this attack.
- [crypto-lab-enigma-forge](https://systemslibrarian.github.io/crypto-lab-enigma-forge/) — statistical cryptanalysis a generation earlier.
- [crypto-lab-vigenere-break](https://systemslibrarian.github.io/crypto-lab-vigenere-break/) — bias-counting against a classical cipher.

## Build & Verify

**121 unit tests** (Vitest, colocated in `src/`), including these known-answer tests:

| KAT | Source | File |
| --- | --- | --- |
| Two published linear approximations of the Heys S-box (12/16 and 4/16) | Heys, *A Tutorial on Linear and Differential Cryptanalysis*, §3.2 | `src/crypto/lat.test.ts` |
| Maximum LAT entry 6/16 (Heys) and 4/16 (PRESENT) | Heys; Bogdanov et al., CHES 2007 | `src/crypto/lat.test.ts` |
| S-box tables | Heys tutorial; PRESENT spec, Table 1 | `src/crypto/sbox.test.ts` |
| Piling-up lemma worked example, total bias −1/32 | Heys tutorial | `src/crypto/trail.test.ts` |
| Algorithm success rates 84.1% / 92.1% / 97.7% / 99.8% at ¼, ½, 1, 2 × ε⁻² | Matsui, *Linear Cryptanalysis Method for DES Cipher*, §4 | `src/crypto/attack.test.ts` |
| Three-round hull: masks 0x01→0x50 match 128/256 vs 130/256 inputs under keys 0x0000 vs 0x1234 | exhaustive measurement of this toy; compare Ashur and Rijmen, ePrint 2016/088 | `src/crypto/trail.test.ts` |
| Two-mask joint outcomes and a no-trail pair with 128/256 matches across 256 sampled toy keys | Beyne and Rijmen, *Linear Cryptanalysis* (2025), chapters 6 and 8 | `src/crypto/advanced.test.ts` |
| Finite-population variance from independently enumerated hypergeometric subsets, distinct sampling, Wilson interval endpoints | Beyne and Rijmen, *Linear Cryptanalysis* (2025), ch. 4 | `src/crypto/attack.test.ts` |
| 96 cross-implementation cipher vectors reproducing crypto-lab-biham-lens's ciphertexts | generated from that repo's own implementation | `src/crypto/spn.test.ts` |
| Differential prefix DDT, signed fixed-RHS path sum, key-dependent full-codebook biases, 256-byte/16-nibble candidate boundaries, holdout vector and deterministic success curves | Langford and Hellman, CRYPTO '94; Biham, Dunkelman and Keller, ASIACRYPT 2002; independent exhaustive enumeration of this toy | `src/crypto/difflin.test.ts` |

Beyond the KATs, the suite pins the claims the demo makes on screen: that the attack recovers the subkey nibble for every key over the full codebook; that it fails on the four-round cipher; that the LAT satisfies Parseval's identity and the trail correlations match a brute-force count over the real round function; and — exhaustively, over all 3,208 candidate mask pairs — that none of them names the correct low nibble for every test key under the Heys S-box, which is why the UI reports that nibble as resistant rather than showing an unexplained failure.

**29 behaviour tests** (Playwright, `e2e/behaviour.spec.ts`) cover what axe cannot — the demo's story and its state machine. Each pins the key and sampling seed through the URL, so a failure means the narrative changed, not that a random draw went the other way. The differential–linear checks pin the join, fixed Heys/3-round boundary, heuristic stack, byte and nibble candidate spaces, aligned recovery, held-out verification, control cancellation, finite-sample control wording, tie ranks, stale rankings, URL persistence and stale or in-flight success curves. Existing checks still cover the default attack, sampling, advanced relations, hidden-key lifecycle, copied links, keyboard reachability, reduced motion and horizontal reflow at 320, 390, 768 and 1440px.

**Accessibility is gated in CI.** `@axe-core/playwright` scans the dark-theme production build for WCAG 2.1 A/AA violations at wide and 380px viewports, after a spec drives every exhibit through its learner-visible states, including both differential–linear designs and the measured curve. Zero violations, or the deploy does not run. (This gate has already caught two real defects: a hover state that dropped white-on-indigo to 4.46:1, and a muted-on-tinted LAT cell.)

**Fifteen targeted mutations are gated in CI.** Each mutation first proves its named browser test is green on an exact baseline artifact, changes one security-critical line, requires an assertion failure with zero retries or skips, restores the source, then proves the artifact hash and owning test return to baseline. The exact per-mutant hashes, diffs and assertion failures are retained as the workflow's `differential-linear-mutation-evidence` artifact instead of committing evidence that would go stale after the next source change.

**Visual regression** (`npm run test:visual`) covers the cockpit after a successful break and after a failed one, in both themes. It is deliberately *not* part of the deploy gate: Playwright baselines are per-platform, and a macOS snapshot fails on the Linux runner for reasons unrelated to the change — a gate that cries wolf is a gate people learn to ignore.

## Performance

No backend; everything runs in the browser. The trail search composes a 256×256 correlation matrix (~17M multiply-compares per round), memoised per S-box; screening runs the attack over the full codebook for twelve keys per candidate. The attack itself precomputes the sixteen per-ciphertext parities once, so counting a batch stays cheap enough to run inside a frame without dropping the count. The original success-rate measurement runs 300 attacks; the optional sampling comparison runs 480. Both run in a Web Worker with real progress reporting and can be cancelled.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

## Reduced-round ChaCha context

The live demo links [EUROCRYPT 2025 bit-puncturing research](https://eprint.iacr.org/2025/437), labels reduced-round results and paper estimates, and distinguishes them from full ChaCha20 and from the attacks these labs actually execute. No reduced-round cipher replaces normal encryption.
