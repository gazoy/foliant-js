# Changelog

`foliant-client`, the TypeScript client. Versions follow [semantic versioning](https://semver.org)
with the usual 0.x caveat. Where a release changes behaviour an existing caller could depend on,
this file says so in the entry rather than only in the version number.

## 0.2.0 — 2026-10-03

The review record for this release is in `audits/`: AUDIT-1 covers the migration itself, AUDIT-2
the remediation that followed.

### Known issues

- **`AgentSigner` meters against a clock the node supplies.** `Agent.submit`, `payChannel` and
  `payPool` all take `now` from `GET /ledger/now`, and `SpendWindow.spent` prunes on
  `now - windowSecs`, so a node that advances its clock between calls empties the window and
  `per_window_max` is not enforced in the signer at all. Measured: ten transfers of 100 signed
  against a `per_window_max` of 150 with an advancing clock, one with a fixed clock. Spec §9 says
  `now` is the evaluator's clock; the Python reference reads it from an in-process ledger and so
  never faced this. The ledger re-enforces with its own clock on the on-chain path, so the exposure
  is the enclave-side bound alone. The fix is architectural — the signer needs a local monotonic
  clock — and is not in this release.

### Changed — breaking

- **`PublicKey.verify` throws `InvalidKey` for an unimplemented scheme**, as the Python reference
  does, rather than a bare `Error`. `InvalidKey extends Error`, so a `catch` or an
  `instanceof Error` is unaffected; a caller discriminating on the exact constructor is not.

- **`escalation` may now be an address string as well as a key reference**, and anything else is a
  `PolicyViolation`. This is one deliberate narrowing against the reference, which returns any
  truthy non-object value unchanged: the schema admits only `null`, an address and a key
  reference, and a co-signer that is not a key can never satisfy the ledger's signer comparison.
  The consequence is that this client cannot attach to an account whose stored policy carries such
  a value, where the reference can.

- **Protocol integers are `bigint`.** `Policy` amounts, `window_secs` and `expiry`, account
  balances and spends, channel and pool deposits and balances, sequence numbers, nonces and ledger
  timestamps all changed from `number` to `bigint`. Callers pass `100n` where they passed `100`.
  `Policy.fromDict` and the `Policy` constructor refuse an amount given as a `number` rather than
  coercing it, because a number reaching them is either already rounded or about to be, and
  accepting the small ones would hide the defect until the first large one.

- **`canonical()` refuses a `number` at every magnitude**, not only above 2^53. Python's
  `json.dumps` writes an `int` as `1` and a `float` as `1.0`; JavaScript has one numeric type in
  which those are the same value, so no inspection of a number says which bytes Python would have
  written, and the two hash differently. A caller that was passing small numbers through
  `canonical` or `hashObj` now gets an error where it used to get bytes — and where, for an
  integral float, it used to get the wrong bytes.

- **The `Policy` constructor validates and canonicalises.** It accepted anything before; it now
  applies the whole of `Policy.__post_init__` (§2 ranges, §2.1 address canonicalisation), so a
  policy that was out of range throws `PolicyViolation` where it used to be constructed, and a
  policy written with mixed-case addresses now has the id the node computes rather than one of its
  own. That changed id is the fix, not a side effect of it.

- **`PolicyDict.escalation` and `Policy.escalation` are unions.** §2 allows an address string as
  well as a key reference, so the types are `PublicKeyDict | string | null` and
  `PublicKey | string | null`. Code that read `policy.escalation.hex` without a check no longer
  compiles, which is the point: before, that code threw at runtime on a policy the node accepted.

- **`npm run build` uses `tsconfig.build.json`.** `tsconfig.json` now covers `src` and `tests`, so
  `tsc --noEmit` type-checks the tests; the build project is the one that emits `dist` from `src`.

### Fixed

- **A policy with amounts at or above 1e21 hashed to a different id here than in the Python
  reference.** `canonical()` rendered such a value the way JavaScript does, `1e+21`, where Python
  writes the digits, so `Agent.attach` and `refresh` disagreed with the ledger about which policy
  the signer was enforcing. `canonical()` now takes `bigint` and emits the digits at every
  magnitude, and refuses a plain `number` instead of hashing something the ledger will not
  recognise. The magnitude test this release first shipped was wrong in both directions: it
  refused `2**53`, which Python renders identically, and admitted the one shape the two
  implementations disagree about — an integral float, which Python writes as `1.0`. Combined with
  `parseJsonBig` leaving a non-integer literal as a `number`, a node or proxy that wrote an amount
  with a trailing `.0` reproduced exactly the unverifiable-signature failure this release set out
  to end.

- **A channel or pool update above 1e21 produced a signature the Python node could not verify.**
  `AgentSigner.signUpdate` puts `balance` straight into the signed body, so the same divergence
  reached the signature. Covered now by a cross-language vector: a balance of
  123456789012345678901 signed by `foliant/crypto.py` and verified here.

- **Amounts above 2^53 were rounded while being read from the node.** `JSON.parse` of
  `1234567890123456789` yields `1234567890123456768`, so the digits were lost before any of this
  library saw the object; at 18 decimals that is roughly 0.009 of a token, which is to say almost
  any realistic amount. `LedgerNode` now parses responses with `parseJsonBig`, which reads each
  integer from the literal as written, and serialises requests with `canonical`, which writes
  `bigint` digits where `JSON.stringify` throws. `parseJsonBig` requires Node 22 or later; on an
  older runtime it throws rather than returning a rounded one.

- **`parseJsonBig`'s fallback refused documents that lose nothing and admitted documents that do.**
  The detection was a digit-run test over the raw document text. A 16-digit run is only lossy above
  9007199254740991, and the test also fired on digits inside strings and on object keys, so an
  ordinary `/ledger/accounts/{id}` response was refused about one time in 740 on its hex ids alone
  (about one in 2,280 per 64-character id, with three independent ids in a root account's response
  and four in a child's), and every response for an account whose policy amounts have 16 or more
  digits was refused outright. Meanwhile exponent forms slipped past it: `1e30` and
  `12345678901234567890e0` do lose digits and were admitted.

  The fallback is now removed rather than repaired. A scan can say which literals `JSON.parse`
  would misread, but the integers in a document it admitted would still come back as `number`,
  which is not what this package's types say — so there is no sound inexact path, only an
  unsupported runtime. `parseJsonBig` throws on a runtime without reviver source access, whatever
  the document contains, and `engines` says the same thing to the installer.

- **A number literal that is not plain digits is refused at the parse.** `1e30`, `12345678901234567890e0`
  and `1.0` cannot be carried: the first two are not the integer they spell once they are doubles,
  and the third would have to be re-emitted as `1.0` to hash the way Python hashes it, which
  `canonical` cannot do from a `number`. `1e400` matters most: it overflows to `Infinity`, and
  `Infinity` compares false against every `bigint`, so it walked through `Agent.payChannel`'s
  `balance > ch.deposit` guard and got an update signed for any amount at all. A genuine fraction
  is still returned, and `canonical` refuses it in turn.

- **The deposit guards compared values the node sent without checking them.** `LedgerNode.call`
  ends in `parseJsonBig(...) as T`, which is an assertion rather than a check, and
  `bigint > undefined`, `bigint > "100"` and `bigint > {}` are all `false` — so a node that omitted
  `deposit`, or sent it as a string or an object, got a channel or pool update signed for any
  amount. Under spec §7.1 that guard is the only bound an off-chain update has. `payChannel` and
  `payPool` now read `deposit`, `balance_to_payee`/`paid`, `seq` and `epoch` through a check that
  refuses anything that did not arrive as a `bigint`.

- **`package.json` declared no `engines`.** `parseJsonBig` needs `JSON.parse`'s reviver source
  argument, which is Node 22 and later. Installing on Node 20 succeeded and landed silently in the
  degraded fallback, where an integer came back as a `number` and failed at the first `bigint` call
  site. `engines` now says `">=22"`.

- **Addresses were never canonicalised.** §2.1 requires every address canonicalised on input — the
  policy's lists when a policy is loaded, the payee when a spend is evaluated — and this client did
  neither, where `Policy.__post_init__` and `Policy.check` both do. Three consequences, all of them
  live: a policy written with mixed-case addresses hashed to an id the node never computes, so
  `Agent.register` failed with "registration body does not match parameters"; a deny-listed
  provider whose channel payee was stored in another case kept getting updates signed; and an
  allow-listed payee in the wrong case could never be paid. Conformance vectors `check-030` and
  `check-031` exist for exactly this and now pass, along with the rest of the specification's
  `check` and `policy` vectors, which are run from the reference repo rather than paraphrased.

- **A policy from the node was not range-checked.** `Policy` bounded nothing and `Policy.fromDict`
  bounded only `expiry`, where the reference bounds `per_tx_max` and `per_window_max` to
  `[0, 2^128)`, `window_secs` to `[1, 2592000]` and `expiry` to `[1, 2^64 - 1]`. This is reachable
  from a hostile or broken node, not merely from local construction, and `window_secs: 0` was a
  fail-open rather than a nuisance: `SpendWindow.spent` prunes with `t > now - window_secs`, so at
  zero every entry is dropped the instant it is recorded, `spentInWindow` is always zero and
  `per_window_max` stops existing in the signer. The `AgentSigner` is there so that the enclave
  does not take the node's word for the policy, so the bounds are applied wherever a policy enters:
  the constructor, and so `fromDict`, `Agent.attach` and every `refresh`.

- **An address-form escalation co-signer crashed `Agent.attach`.** §2 and `_escalation` in
  `foliant/accounts.py` allow `escalation` to be an address as well as a key reference, so a Python
  node accepts and stores one; `Policy.fromDict` called `PublicKey.fromDict` on it unconditionally
  and threw a raw `TypeError: hex string expected, got undefined` from inside `@noble` — against a
  policy the node considered perfectly valid. This is the gap 0.1.2 recorded as belonging with the
  `bigint` work. An address co-signer is canonicalised like any other address and the all-zero
  address is refused, as §2 requires.

- **`PublicKey.fromDict` validated almost nothing.** It was
  `new PublicKey(d.scheme, hexToBytes(d.key))`. Bad hex and a missing `key` surfaced as a raw
  `TypeError` or `RangeError` from inside `@noble` rather than as anything a caller could catch, an
  unknown nested field was dropped although the schema forbids it — which, for a key inside a
  signed policy, meant the id covered less than the signer wrote — and a two-byte string was
  accepted as an ed25519 public key, leaving an account holding a co-signer that cannot verify
  anything while the owner believes an escalation path exists. The rules and the messages are now
  those of `PublicKey.from_dict` in `foliant/crypto.py`, and the rejection is a new `InvalidKey`
  error (the counterpart of the reference's), which `Policy.fromDict` translates into
  `PolicyViolation` so that an invalid policy reports as an invalid policy whichever part of it is
  invalid. This closes the nested-field gap 0.1.2 recorded under Known issues.

- **`Policy.fromDict` admitted an expiry of 2^64.** The schema's maximum is 2^64 - 1, which no
  double represents, so the bound was tested as an exclusive 2^64. As a `bigint` the bound is
  exact and is now written as the schema writes it.

### Added

- `parseJsonBig` and the `big_integers` vectors in `tests/vectors.json`, generated by
  `foliant/crypto.py`, so agreement with the reference at these magnitudes is measured rather than
  assumed.

- `InvalidKey`, `canonicalAddress` and `SCHEME` are exported; `parseJsonBig` takes the
  runtime-capability flag as a second argument, so its fallback can be tested on a runtime that
  has the exact path.

- `prepublishOnly`, which builds and tests before publishing. `dist/` is gitignored and `files` is
  `["dist"]`, so `npm publish` was shipping whatever happened to be on disk.

- Tests: the specification's own `check` and `policy` conformance vectors, run from the reference
  repo; the key-reference cases of the reference's `tests/test_keyref.py`; `parseJsonBig`'s
  detection in both directions and on both paths; and the signing path — `payChannel`, `payPool`,
  `signUpdate` and `Policy.check` — above 2^53 against a stubbed node, which the suite exercised
  only at `30n` before. The served devnet caps its faucet at 1,000,000 a call, so the live node
  cannot be funded to those magnitudes; the cross-language half of that case is the
  `big_integers` vectors.

- `tsconfig.json` now includes `tests`, so `tsc --noEmit` type-checks them. It did not, which left
  this release's central claim — that no protocol integer is a `number` any more — unenforced in
  the one place it is written down.

## 0.1.2 — 2026-10-02

### Fixed

- **`Policy.fromDict` now rejects a policy carrying a field this client does not implement**,
  throwing `PolicyViolation`, instead of silently discarding it. `Policy.id` is derived from
  `toDict()`, which rebuilds only the seven fields this client knows, so an unknown field vanished
  from the hash: the same policy with and without a per-asset cap produced the same id, and the
  cap the owner wrote and signed over was simply not there. `Agent.register` computes that id
  client-side for the owner to sign, and `Agent.attach` and `refresh` rebuild the policy the signer
  enforces locally, so the drop could both widen what the owner signed and weaken what the signer
  checks.

  The rule and the message match `_reject_unknown` in the Python reference
  (`foliant-protocol` 0.1.3), which lands the same fix in the same window. The two
  implementations have to agree on which policies are valid: if one tightened alone, a policy
  accepted by this client would be refused by the node, and a crew spanning both SDKs would get
  different budget semantics depending on which one parsed last.

  A non-object passed to `fromDict` now throws `PolicyViolation` rather than failing later.

- **`Policy.fromDict` also rejects a policy that is *missing* one of the seven fields**, an address
  list that is not a list of distinct strings, and an `expiry` outside `[1, 2^64)` — mirroring
  `foliant-protocol` 0.1.4, which landed the same rules. A missing field is the more dangerous
  half of the unknown-field rule in both implementations: the constructor defaults are the
  permissive readings, `Agent.register` signs the id of whatever this client parsed, and `toDict()`
  then sends all seven fields, so the node accepts a policy weaker than the owner intended without
  anything to object to. The list rules matter for the same reason: a bare string became a `Set` of
  single characters and duplicates were deduplicated, where the schema sets `uniqueItems: true`.

  Not mirrored, deliberately: this client still cannot parse an **address-form** escalation
  co-signer, which §2 permits and `foliant-protocol` 0.1.4 fixed in its envelope encoding.
  `PublicKey.fromDict` expects a keyRef object. That is a missing feature rather than a
  disagreement about validity, and it belongs with the 0.2.0 work.

  The `expiry` bound is tested at `2**64` rather than `2**64 - 1`, because the latter is not
  exactly representable as a `number` — a small instance of the limitation below, inside the fix
  for a different one.

  **In practice this can break a caller** that was passing extra fields through, although
  TypeScript already rejected an excess property on an object literal typed as `PolicyDict`, so
  the realistic source is a value from `JSON.parse`.

### Documented

- A new **Limits** section in the README records that amounts are JavaScript `number`s, so this
  client is correct for assets with up to 6 decimals and not for 18: values above 2^53 are
  silently rounded by `JSON.parse`, and at 1e21 and above `canonical()` emits exponential notation
  where Python emits digits, which makes policy ids diverge between the two implementations and
  makes a channel or pool update at that scale unverifiable by the node. This is not fixed here.
  It needs amounts carried as `bigint` through `Policy`, `SpendWindow`, `signUpdate` and the node
  response parse, which is a breaking API change and is tracked for 0.2.0.

### Known issues

- The nested escalation key object is not checked for unknown fields, although the schema forbids
  them there too. The Python reference has the same gap, deliberately: both are being left for one
  pass rather than diverging.

## 0.1.1 — 2026-09-29

### Changed

- Pool updates carry the claim epoch, and balances are forgotten on exit, so a stale update cannot
  be replayed against a later membership (protocol change AUDIT-2 A2-2).

## 0.1.0 — 2026-09-29

First release, as `@foliant/client` and then renamed to `foliant-client`: keys, addresses,
canonical hashing and signatures byte-compatible with the Python reference and tested against
vectors it produced; the agent, the ledger-node client, and the x402 paying client.
