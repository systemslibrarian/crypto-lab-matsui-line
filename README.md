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
6. **How much traffic do you need?** — Matsui's inverse-square rule, with the sample count for a target success rate, next to the **measured** success rate of the attack run end to end over 60 random keys per data size. That measurement is 300 complete attacks; it runs in a Web Worker and reports real progress, so it stays cancellable and the page stays responsive. The two curves disagree, and the panel explains why.
7. **The pair-mate attack** — differential versus linear across seven properties, with the honest note about how far each reaches on a block this small.
8. **Limits** — what is real here and what this does not prove.

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
- **Assuming the key schedule saves you.** A round-key XOR changes the sign of a linear approximation and nothing else. Key material cannot make a biased relation unbiased — only the non-linear layer can.

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

`npm test` runs the unit suite; `npm run build && npm run test:a11y` runs the production build through the accessibility gate.

## Related Demos

- [crypto-lab-biham-lens](https://systemslibrarian.github.io/crypto-lab-biham-lens/) — differential cryptanalysis of the same toy SPN. The pair-mate attack, and the direct comparison this demo is built against.
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — the cipher whose S-box was chosen to survive this attack.
- [crypto-lab-enigma-forge](https://systemslibrarian.github.io/crypto-lab-enigma-forge/) — statistical cryptanalysis a generation earlier.
- [crypto-lab-vigenere-break](https://systemslibrarian.github.io/crypto-lab-vigenere-break/) — bias-counting against a classical cipher.

## Build & Verify

**88 unit tests** (Vitest, colocated in `src/`), including these known-answer tests:

| KAT | Source | File |
| --- | --- | --- |
| Two published linear approximations of the Heys S-box (12/16 and 4/16) | Heys, *A Tutorial on Linear and Differential Cryptanalysis*, §3.2 | `src/crypto/lat.test.ts` |
| Maximum LAT entry 6/16 (Heys) and 4/16 (PRESENT) | Heys; Bogdanov et al., CHES 2007 | `src/crypto/lat.test.ts` |
| S-box tables | Heys tutorial; PRESENT spec, Table 1 | `src/crypto/sbox.test.ts` |
| Piling-up lemma worked example, total bias −1/32 | Heys tutorial | `src/crypto/trail.test.ts` |
| Algorithm success rates 84.1% / 92.1% / 97.7% / 99.8% at ¼, ½, 1, 2 × ε⁻² | Matsui, *Linear Cryptanalysis Method for DES Cipher*, §4 | `src/crypto/attack.test.ts` |
| 96 cross-implementation cipher vectors reproducing crypto-lab-biham-lens's ciphertexts | generated from that repo's own implementation | `src/crypto/spn.test.ts` |

Beyond the KATs, the suite pins the claims the demo makes on screen: that the attack recovers the subkey nibble for every key over the full codebook; that it fails on the four-round cipher; that the LAT satisfies Parseval's identity and the trail correlations match a brute-force count over the real round function; and — exhaustively, over all 3,208 candidate mask pairs — that none of them names the correct low nibble for every test key under the Heys S-box, which is why the UI reports that nibble as resistant rather than showing an unexplained failure.

**14 behaviour tests** (Playwright, `e2e/behaviour.spec.ts`) cover what axe cannot — the demo's story and its state machine. Each pins the key and sampling seed through the URL, so a failure means the narrative changed, not that a random draw went the other way: the default scenario recovers the expected nibble; a failed attack never badges a wrong guess as the key; starved data reports honestly; changing a control retires the previous result; the key stays hidden until revealed or earned; a copied experiment link reproduces the ranking exactly; the primary action sits in the first viewport and is keyboard-reachable; reduced motion reaches the same final values without the counting animation; and no layout overflows at 320, 390, 768 or 1440px.

**Accessibility is gated in CI.** `@axe-core/playwright` scans the production build for WCAG 2.1 A/AA violations in both themes and at a 380px viewport, after a spec that drives every exhibit into its post-interaction states — idle, counting, done, stale, and blocked; every scenario preset; the rejected-mask state; and the measured success curve. Zero violations, or the deploy does not run. (This gate has already caught two real defects: a hover state that dropped white-on-indigo to 4.46:1, and a muted-on-tinted LAT cell.)

**Visual regression** (`npm run test:visual`) covers the cockpit after a successful break and after a failed one, in both themes. It is deliberately *not* part of the deploy gate: Playwright baselines are per-platform, and a macOS snapshot fails on the Linux runner for reasons unrelated to the change — a gate that cries wolf is a gate people learn to ignore.

## Performance

No backend; everything runs in the browser. The trail search composes a 256×256 correlation matrix (~17M multiply-compares per round), memoised per S-box; screening runs the attack over the full codebook for twelve keys per candidate. The attack itself precomputes the sixteen per-ciphertext parities once, so counting a batch stays cheap enough to run inside a frame without dropping the count. The success-rate measurement — 300 complete attacks — runs in a Web Worker with real progress reporting and can be cancelled.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
