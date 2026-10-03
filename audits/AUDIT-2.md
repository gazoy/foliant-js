# AUDIT-2: the remediation of AUDIT-1

Date: 2026-10-03
Target: the fixes for AUDIT-1 F-1 to F-7 and the packaging items, as merged into 0.2.0.
Method: two implementers worked the same brief independently, in isolated copies, without sight of
each other. Each implementation was then reviewed by its own independent reviewer. A fifth
reviewer audited the two reviews, cross-applied every finding to the other implementation and to
the unfixed baseline, and recommended what to merge.

## 1. Why two implementations

The two agreed on nine of the ten items and diverged on one — what to do about `parseJsonBig` on a
runtime without reviver source access. A rebuilt the detection properly; B deleted the fallback
outright. Having both let the fifth reviewer evaluate a decision rather than a defence of one, and
the answer turned out to be that the question had two halves and each implementation answered a
different half correctly.

## 2. The finding that justified the exercise

**Neither reviewer of the original work found what the other found, and the cross-application was
where the real defects surfaced.**

### D-1 Medium: the deposit guard is bypassable, and the parser is only one of four routes

`parseJsonBig` admitted any literal overflowing to `±Infinity`, because `Number.isInteger(Infinity)`
is `false`. A node serving `"deposit": 1e400` therefore gave `ch.deposit === Infinity`, and
`balance > Infinity` is false for every `bigint`, so `Agent.payChannel` signed an update of
arbitrary size. Under §7.1 that guard is the only bound an off-chain update has.

The fifth reviewer then found three more routes to the same bypass that have nothing to do with
number parsing: `LedgerNode.call` ends in `parseJsonBig(...) as T`, an assertion rather than a
check, and `bigint > undefined`, `bigint > "1e400"` and `bigint > {}` are all `false`. **An absent,
string or object `deposit` signed a 10^30 update in all three trees**, including the unfixed one.
Fixing the parser closes one route of four.

Both are fixed: the reviver refuses non-finite literals, and `payChannel`/`payPool` read `deposit`,
`balance_to_payee`/`paid`, `seq` and `epoch` through a check that refuses anything that did not
arrive as a `bigint`.

### D-2 Medium: `per_window_max` is still disableable by the node, through `now`

Raised by B's reviewer, confirmed in all three trees including the baseline. `Agent.submit`,
`payChannel` and `payPool` take `now` from `GET /ledger/now`, and `SpendWindow.spent` prunes on
`now - windowSecs`, so a node advancing its clock empties the window. Measured: **ten transfers of
100 signed against a `per_window_max` of 150** with an advancing clock, one with a fixed clock.

Spec §9 says `now` is the evaluator's clock. The Python reference reads it from an in-process
ledger and so never faced this; this client fetches it over HTTP from the party the signer exists
to distrust. The fix is architectural — the signer needs a local monotonic clock — so it is **not**
in this release and is recorded as a Known Issue in the CHANGELOG instead.

### D-3: an implementation regressed against the reference while fixing it

A's `escalationField` refused `escalation: 0`, `false` and `0.0`, which Python's `esc or None`
normalises to `None` and which the baseline handled correctly. A regression introduced by the
remediation, caught only because B had implemented the same function differently and the fifth
reviewer ran a differential that covered the field. Both reviewers' own differentials under-sampled
`escalation` and reported clean.

## 3. The item-3 decision, as settled

On what to do about an unsupported runtime, **B was right**: a package that declares one supported
runtime in `engines` and then ships a half-working path for another has two configurations and
tests one. A's degraded path returned `number` where the published types promise `bigint`, and was
not actually tested on the runtime it served — its tests reached it through an injected flag, where
the reviver still receives its context, so the real pre-22 path remained unreached, which is
exactly how the original regex survived a release.

On what to do about a non-plain-digit literal on the supported path, **A was right**: A refuses
`1e30`, `1e2`, `2.00` and `12345678901234567890e0` at the parse; B's live reviver converted only
`/^-?\d+$/` and returned the rest untouched, so `{"deposit": 1e30}` became a `number` and walked
through the deposit guard with a far more plausible literal than `1e400`.

Merged: B's outcome for the unsupported runtime, A's refusal on the supported one.

## 4. What was merged

Basis: implementation A — it ran the specification's own vectors from the reference repo rather
than paraphrasing them, which is what makes "this client agrees with the spec" a measured claim.

Taken from B: the whole of `escalationField` (D-3); the `parseJsonBig` structure that throws on an
unsupported runtime; the JSDoc layout that puts the parse documentation on the function rather than
on a constant beside it; and `tests/agent.test.ts`, the only place either tree drives `attach` and
`payPool` against responses a cooperative node will not send.

Added on top: the non-finite refusal, the view checks at both deposit guards and their tests, a
publishable `prepublishOnly` (`test:unit`, excluding the two suites that need the Python checkout),
a `describe.skipIf` so the conformance suite skips rather than fails when the reference is absent,
and the documentation corrections below.

## 5. Documentation defects, which both reviewers flagged separately

Both implementations shipped prose that was false, in opposite ways, and both were corrected:

- A said the refusal was "exactly the set of documents `JSON.parse` cannot read". It refused `1e2`,
  `2.00` and `1000e-3`, which are exact, and admitted `1e400`, which is not.
- A and B both justified refusing `1.0` with "no implementation can carry it exactly", which is
  simply untrue — `1e2` is 100. The sound argument is that a JavaScript `number` cannot be
  re-emitted as Python's `1.0`, so the canonical round trip is lost.
- B said no protocol operation could complete on a pre-22 runtime. Demonstrated false: `now`,
  `balance`, `faucet`, `account` and `Agent.register` all completed at the baseline; only the paths
  through `Policy.fromDict` threw. The decision to remove the fallback is still right, for the
  structural reason in §3, but not for the reason given.
- Both stated the old false-refusal rate as 1 in 2,250 of an account response. That is the per-id
  figure. Re-measured over 300,000 synthetic responses of the real shape: **1 in 730**.

## 6. Verification

142 tests across 8 files; `tsc --noEmit` clean over `src` and `tests`; 31 of 31 `check` vectors and
8 of 9 `policy` vectors from the reference agree (`policy-005` is a wire-form grammar case this
client has no `from_wire` to reach); the e2e suite runs against a live `demo/serve.py`; and
`npm run test:unit` — the publish gate — passes with no reference checkout present.

## 7. Open, and deliberately not in this release

D-2 above, the node-supplied clock. Also carried forward from AUDIT-1: `rewindow` on `refresh()`,
x402 channel discovery from the ledger, the `defaultDeposit` 100-vs-1000 divergence, code-point key
sorting, and `Policy.within`/`wire()`/`spec_id`, which this client does not implement at all.
