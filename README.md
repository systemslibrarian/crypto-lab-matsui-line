# crypto-lab-matsui-line

## What It Is

**Linear cryptanalysis** is a known-plaintext attack on block ciphers, published by Mitsuru Matsui in 1993 and used by him in 1994 for the first experimental break of full DES. It works by finding linear approximations — statements of the form "this XOR of plaintext bits equals that XOR of round-input bits" — that hold slightly more often than half the time because the cipher's S-boxes are not perfectly balanced. The **piling-up lemma** describes how those small biases compound across rounds, and **Matsui's Algorithm 2** turns the surviving bias into key bits: guess part of the final subkey, undo the last round under each guess, and see which guess makes the bias appear.

This demo implements the attack against the same toy 4-round SPN that [crypto-lab-biham-lens](https://systemslibrarian.github.io/crypto-lab-biham-lens/) attacks with differentials — 8-bit block, 16-bit key, a 4-bit S-box on each nibble, and a bit permutation for diffusion. Every ciphertext on the page comes out of that real cipher, every bias is counted rather than asserted, and the trail search is exhaustive over the 8-bit mask space rather than a heuristic.

**This is not production cryptography.** An 8-bit block has 256 plaintexts; the entire codebook fits in a browser tab, and the cipher is broken by definition. It exists so the attack is visible at a scale you can watch. Breaking it proves nothing about AES or DES — it demonstrates the mechanism that forced their designs.

The security model on display is deliberately generous to the attacker in one way and strict in another: they see plaintext/ciphertext pairs they did not choose (weaker access than differential cryptanalysis needs), and they never touch the key — the demo checks their answer against the real key only after the attack has finished.

## Exhibits

1. **The cipher under attack** — pick the S-box (Heys' textbook toy, or PRESENT) and the round count, slide a plaintext through, and watch every intermediate state in binary. The last round's key XOR is marked: it is the state the attack aims at.
2. **Every leak the S-box has** — the full 16×16 linear approximation table. Each cell is a button; selecting one shows all 16 inputs with both sides of the approximation computed independently and compared, so the table's number is visibly the sum of that column rather than a claim. Cells the current trail rides on are ringed.
3. **Watch the bias compound** — step through the trail one round at a time and watch the piling-up lemma shrink the bias, shown in both its bias form (ε = 2ⁿ⁻¹ ∏ εᵢ) and its correlation form. A disclosure panel then measures the true bias by running the real cipher over all 256 plaintexts, for ten different keys — which is where the **linear hull effect** shows up: over two rounds the lemma is exact — every key gives |ε| = 1/8 on the nose and only the sign moves — while over three rounds the measured bias scatters with the key. Take the strongest three-round trail the lemma can find (the *unverified* setting in exhibit 4) and its true bias ranges from 5/64 down to *exactly zero* across ten keys, while the prediction sits unmoved at 27/512.
4. **Recover the key** — Matsui's Algorithm 2. Choose the target nibble, the amount of traffic, and the approximation (screened, unscreened, or your own masks); the ranking of all sixteen candidates appears with the real key marked. Three levers break it: cut the data, add a round, or supply a hopeless approximation.
5. **How much traffic do you need?** — Matsui's inverse-square rule, with the sample count for a target success rate, next to the **measured** success rate of the attack run end to end over 60 random keys per data size. The two disagree, and the panel explains why.
6. **The pair-mate attack** — differential versus linear across seven properties, with the honest note about how far each reaches on a block this small.

## When to Use It

- **Evaluating a new block cipher or S-box.** Computing the LAT and searching for multi-round trails is one of the first things a designer does; a maximum LAT entry that is too large is a disqualifying result.
- **Justifying round counts.** The inverse-square data requirement is what turns "one more round" into "four times the traffic", and it is the argument behind the round counts in AES, PRESENT, and Serpent.
- **Teaching why non-linearity matters.** The S-box is the only non-linear component; the attack is a demonstration of what happens to the parts of a cipher that are linear.
- **Analysing legacy or bespoke ciphers.** Ciphers designed before 1993, or designed without cryptanalytic review, frequently have exploitable linear approximations.
- **When NOT to use it:** do not reach for linear cryptanalysis against a modern standardised cipher and expect a result — AES, ChaCha20 and their peers were designed specifically to make the required data exceed the number of blocks the mode will ever encrypt. And **do NOT treat the toy SPN here as a cipher**: it is a teaching target, not cryptography.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-matsui-line](https://systemslibrarian.github.io/crypto-lab-matsui-line/)**

Open it and the attack has already run against the whole codebook: one candidate stands alone at the top of the ranking, and it is the key. From there you can take the data away with the slider and watch it stop working, add the fourth round and watch the ranking dissolve into noise, swap the S-box, invent your own masks, or press *Measure the real success rate* and get a curve produced by running the attack 300 times rather than by evaluating a formula.

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

**84 unit tests** (Vitest, colocated in `src/`), including these known-answer tests:

| KAT | Source | File |
| --- | --- | --- |
| Two published linear approximations of the Heys S-box (12/16 and 4/16) | Heys, *A Tutorial on Linear and Differential Cryptanalysis*, §3.2 | `src/crypto/lat.test.ts` |
| Maximum LAT entry 6/16 (Heys) and 4/16 (PRESENT) | Heys; Bogdanov et al., CHES 2007 | `src/crypto/lat.test.ts` |
| S-box tables | Heys tutorial; PRESENT spec, Table 1 | `src/crypto/sbox.test.ts` |
| Piling-up lemma worked example, total bias −1/32 | Heys tutorial | `src/crypto/trail.test.ts` |
| Algorithm success rates 84.1% / 92.1% / 97.7% / 99.8% at ¼, ½, 1, 2 × ε⁻² | Matsui, *Linear Cryptanalysis Method for DES Cipher*, §4 | `src/crypto/attack.test.ts` |
| 96 cross-implementation cipher vectors reproducing crypto-lab-biham-lens's ciphertexts | generated from that repo's own implementation | `src/crypto/spn.test.ts` |

Beyond the KATs, the suite pins the claims the demo makes on screen: that the attack recovers the subkey nibble for every key over the full codebook; that it fails on the four-round cipher; that the LAT satisfies Parseval's identity and the trail correlations match a brute-force count over the real round function; and — exhaustively, over all 3,208 candidate mask pairs — that none of them names the correct low nibble for every test key under the Heys S-box, which is why the UI reports that nibble as resistant rather than showing an unexplained failure.

**Accessibility is gated in CI.** `@axe-core/playwright` scans the production build for WCAG 2.1 A/AA violations in both themes and at a 380px viewport, after a spec that drives every exhibit into its post-interaction states — including all three attack verdicts, the rejected-mask state, and the measured success curve. Zero violations, or the deploy does not run.

## Performance

Everything runs on the main thread with no backend. The trail search composes a 256×256 correlation matrix (~17M multiply-compares per round) and is memoised per S-box; screening runs the attack over the full codebook for twelve keys per candidate. The measured success-rate curve is the heaviest action on the page — 300 complete attacks — and takes on the order of a second.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
