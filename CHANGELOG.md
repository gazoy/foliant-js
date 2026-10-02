# Changelog

`foliant-client`, the TypeScript client. Versions follow [semantic versioning](https://semver.org)
with the usual 0.x caveat. Where a release changes behaviour an existing caller could depend on,
this file says so in the entry rather than only in the version number.

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
