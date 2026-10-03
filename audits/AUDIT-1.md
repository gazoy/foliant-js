# AUDIT-1: `foliant-client` 0.2.0, the bigint migration

Date: 2026-10-03
Target: commit `d70ceda`, "Carry protocol integers as bigint", against the Python reference
(`concord` at `foliant/`, `docs/spec/spending-policy.md`, `docs/spec/vectors.json`).
Reviewers: two independent reviewers, neither of whom wrote the code, working from the same brief
without sight of each other's work; their findings were then reviewed by a third.

## 1. Scope and method

`d70ceda` moved every protocol integer from `number` to `bigint` and changed how documents are
read and written on the wire. The question for review was whether it did what it claimed and
whether it introduced anything.

Each reviewer read the diff, ran the suite and the typecheck, wrote probes, and compared behaviour
against the reference by running it — not by reading it. Both regenerated the `big_integers`
vectors from `foliant/crypto.py` independently and confirmed they are what they claim
(policy id `73ba6541…`, signature `3549c9b8…`). Both fuzzed `canonical()` against
`json.dumps(sort_keys=True, separators=(",",":"))` over thousands of structures. Both drove live
round trips against `demo/serve.py`.

The third reviewer re-ran every claim rather than accepting it, resolved the two places the first
two contradicted each other, and looked for what both had missed.

## 2. Verdict on the migration itself

The three fixes `d70ceda` claimed all hold, and were verified against the reference rather than
against the suite:

- `canonical()` emits digits at every magnitude. `String(bigint)` never uses exponent form, so the
  `1e+21` divergence is genuinely closed.
- The signature over a balance of 123456789012345678901 is byte-identical to the reference's.
- `LedgerNode` no longer rounds integers while reading them.

## 3. Findings

Severities are the third reviewer's, after re-measurement. One finding was raised as High by the
first reviewer and downgraded; the reasoning is recorded at F-1 because it is the useful part.

### F-1 Medium: addresses are never canonicalised (pre-existing)

Python lowercases `0x…` addresses in the policy's lists and on the payee at evaluation; this client
did neither. Conformance vectors `check-030` and `check-031` exist for exactly this and failed:
`check-030` refused a payee the reference allows, `check-031` **allowed a payee the reference
denies**.

Reproduced live: a provider added to the deny list after a channel is open kept getting updates
signed, because the node canonicalises the list but stores the channel payee verbatim, and
settlement never re-checks policy.

Rated Medium rather than High on three bounds, all verified: the only fail-open surface is
`signUpdate`, and spec §7.1 says off-chain updates are bounded by the deposit rather than
re-checked; the deposit was itself already checked and recorded against the policy when the channel
opened, so §9's loss bound holds; and every path that could open new exposure — `open_channel`,
`join_pool`, `transfer`, `register` — re-checks on the ledger and fails closed.

### F-2 Medium: `canonical()` renders an integral float as an integer

`canonical({a: 1.0})` gave `{"a":1}` where Python writes `{"a":1.0}` — a different hash. The guard
added in `d70ceda` used `Number.isInteger` and then `Number.isSafeInteger`, and neither can tell
`1` from `1.0` in JavaScript, so it refused `2**53` (which Python agrees about) while admitting the
one shape it disagrees about. Chained with `parseJsonBig` leaving non-integer literals as `number`,
any node or proxy writing an amount with a trailing `.0` reproduces the silent unverifiable-signature
failure the commit set out to end. Found by the third reviewer; both of the first two missed it.

### F-3 Medium: no range validation

Python bounds amounts to `[0, 2^128)`, `window_secs` to `[1, 2592000]` and `expiry` to
`[1, 2^64-1]`; this client checked the type only. Reachable from the node, not merely from local
construction: attached to a node serving `window_secs: 0`, `cutoff = now - 0n` and the filter
`t > cutoff` prunes each entry at the instant it is recorded, so `per_window_max` is not enforced
at all. Measured: ten payments of 100 signed against a cap of 150.

### F-4 Medium: the `parseJsonBig` fallback regex was wrong in both directions

`/(?<![\w.])-?\d{16,}(?![\d.eE])/` ran over the raw document, so it fired on digits inside strings
and on object keys and refused documents that lose nothing, while exponent forms slipped past it.
Measured over 300,000 synthetic responses of the real shape: an ordinary `/ledger/accounts/{id}`
response was refused about **1 in 730**, and every response for an account whose policy amounts
have 16 or more digits was refused outright. The three reviewers first reported 1 in 2,250, 1 in
542 and 1 in 551; the first is the per-id rate, the other two assume four independent ids where
`address` is derived from `id`.

### F-5 Medium: `package.json` declared no `engines`

`parseJsonBig` needs `JSON.parse` reviver source access, which is Node 22. Installing on Node 20
succeeded and landed silently in the degraded path. The one defect here that could not be remedied
after the fact for anyone who had already installed.

### F-6 Low: an address-form escalation co-signer crashed

Spec §2 permits it and the node stores and serves it, so this was an account the reference
considered valid and this client could not open: `Agent.attach` threw a raw `TypeError` from
inside `@noble`.

### F-7 Low: `PublicKey.fromDict` performed almost no validation

Unknown fields, wrong key length and uppercase hex were all accepted; everything it did refuse came
back as a raw `TypeError`/`RangeError` rather than a catchable library error.

### F-8 and below, Low and Informational

The README quickstart no longer compiled; `prepublishOnly` was absent so `npm publish` shipped
whatever was in `dist/`; `canonical()` sorts keys by UTF-16 code unit where Python sorts by code
point (unreachable for ASCII protocol data — one reviewer's 4.5% fuzz rate was not reproducible
from the alphabet it described); `refresh()` replaces the signer's policy without the reference's
`rewindow` step; x402 channel reuse scans only this process's signed updates; `defaultDeposit` is
100 where the reference's is 1000.

## 4. Where the reviewers disagreed

**`defaultDeposit`.** One reviewer said the reference defaults to 1000 and this client to 100, a
10× divergence; the other said 100 matches. `foliant/x402.py` has `default_deposit: int = 1000`.
The first reviewer was right.

**Severity of F-1.** One rated it High, the other Medium. Medium, for the §7.1 reason above —
which is not the reason either of the first two gave.

## 5. Disposition

F-1 through F-7 and the README, `engines` and `prepublishOnly` items are fixed in AUDIT-2's
remediation. `rewindow`, x402 channel discovery, the `defaultDeposit` divergence and code-point
sorting are deferred and recorded here so they are not lost.
