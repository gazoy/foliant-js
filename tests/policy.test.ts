/**
 * Policy validity: the rules of spec §2, as `Policy.__post_init__` and `_check_fields` apply them
 * in foliant/accounts.py. The node answers 400 with these messages, LedgerNode.call turns them
 * back into a PolicyViolation, and a policy the Python reference rejects must not be one this
 * client quietly accepts -- nor the reverse, or a crew spanning both SDKs gets different budget
 * semantics depending on which one parsed last.
 */
import { describe, expect, it } from "vitest";
import { KeyPair } from "../src/crypto.js";
import { AgentSigner, Policy, PolicyViolation, canonicalAddress } from "../src/agent.js";

const good = {
  per_tx_max: 10n, per_window_max: 100n, window_secs: 60n,
  allow_list: null, deny_list: [], expiry: null, escalation: null,
};

describe("Policy.fromDict", () => {
  it("still parses the seven fields, round-tripping to the same id", () => {
    const p = Policy.fromDict(good);
    expect(Policy.fromDict(p.toDict()).id).toBe(p.id);
  });

  it("refuses a field it does not implement, naming every offender in sorted order", () => {
    // before this guard these parsed, and `id` came out identical to the clean policy's: the
    // caps the owner wrote were simply gone, and the signature looked like it covered them
    const poisoned = { ...good, zzz: true, perAssetMax: { USDC: 1 }, meters: [{ unit: "gpu" }] };
    expect(() => Policy.fromDict(poisoned as never)).toThrow(PolicyViolation);
    expect(() => Policy.fromDict(poisoned as never)).toThrow(
      "unknown policy field(s): 'meters', 'perAssetMax', 'zzz'",
    );
  });

  it("refuses a missing field, naming every one", () => {
    // the dangerous half: the constructor defaults are the permissive readings, and register()
    // signs the id of whatever this client parsed, so an omitted field widened what the owner
    // signed -- toDict() then sends all seven and the node accepts it
    for (const dropped of Object.keys(good)) {
      const short = Object.fromEntries(Object.entries(good).filter(([k]) => k !== dropped));
      expect(() => Policy.fromDict(short as never)).toThrow(`missing policy field(s): '${dropped}'`);
    }
  });

  it("refuses an address list that is not a list of distinct strings", () => {
    for (const field of ["allow_list", "deny_list"]) {
      const a = "0x" + "ab".repeat(20);
      // a bare string would become a Set of single characters
      expect(() => Policy.fromDict({ ...good, [field]: a } as never)).toThrow(/must be a list/);
      expect(() => Policy.fromDict({ ...good, [field]: [1] } as never)).toThrow(/entries must be strings/);
      expect(() => Policy.fromDict({ ...good, [field]: [a, a] } as never)).toThrow(/duplicate entries/);
    }
    // null is the allow_list's "any payee"; for deny_list it is not a list
    expect(Policy.fromDict({ ...good, allow_list: null }).allowList).toBeNull();
    expect(() => Policy.fromDict({ ...good, deny_list: null } as never)).toThrow(/must be a list/);
  });

  it("bounds expiry above, as the schema does", () => {
    expect(() => Policy.fromDict({ ...good, expiry: 2n ** 64n } as never)).toThrow(/\[1, 2\^64\)/);
    expect(() => Policy.fromDict({ ...good, expiry: 0n } as never)).toThrow(/\[1, 2\^64\)/);
    expect(Policy.fromDict({ ...good, expiry: 1n }).expiry).toBe(1n);
    // the bound the schema actually writes, which no double represents
    expect(Policy.fromDict({ ...good, expiry: 2n ** 64n - 1n }).expiry).toBe(2n ** 64n - 1n);
  });

  it("refuses a non-object", () => {
    for (const bad of ["abc", 7, null, [good]]) {
      expect(() => Policy.fromDict(bad as never)).toThrow(/policy must be an object, not/);
    }
  });

  it("takes an address-form escalation co-signer, which §2 permits", () => {
    // `_escalation` in foliant/accounts.py accepts a keyRef object, an address string, or null, so
    // a Python node accepts and stores the address form. This client called PublicKey.fromDict on
    // it unconditionally, and `Agent.attach` to such an account threw a raw TypeError out of
    // @noble -- from a policy the node considered perfectly valid.
    const addr = "0x" + "ee".repeat(20);
    const p = Policy.fromDict({ ...good, escalation: addr });
    expect(p.escalation).toBe(addr);
    expect(p.toDict().escalation).toBe(addr); // a string here too, as the reference's to_dict does
    expect(Policy.fromDict(p.toDict()).id).toBe(p.id); // the round trip every refresh() makes
    // canonicalised like any other address (§2.1), so case is not part of the policy's identity
    expect(Policy.fromDict({ ...good, escalation: addr.toUpperCase().replace("0X", "0x") }).id).toBe(p.id);
    // and the zero address is not a co-signer (§2), for the reason expiry 0 is not an expiry
    expect(() => Policy.fromDict({ ...good, escalation: "0x" + "0".repeat(40) }))
      .toThrow(/escalation must not be the zero address/);
    // the key form still parses, and is still a PublicKey
    const key = KeyPair.fromSeed("co-signer").public;
    expect(Policy.fromDict({ ...good, escalation: key.toDict() }).escalation).toEqual(key);
    // neither form, and the schema has no third: refused rather than hashed into an id
    expect(() => Policy.fromDict({ ...good, escalation: 5 } as never))
      .toThrow(/escalation must be a key reference, an address string, or null/);
  });

  it("canonicalises the address lists, as §2.1 requires on input", () => {
    const upper = "0x" + "AB".repeat(20);
    const lower = upper.toLowerCase();
    // the id is what this is really about: a mixed-case policy hashed to an id the node never
    // computes, so Agent.register failed with "registration body does not match parameters"
    expect(Policy.fromDict({ ...good, allow_list: [upper], deny_list: [] }).id)
      .toBe(Policy.fromDict({ ...good, allow_list: [lower], deny_list: [] }).id);
    expect([...Policy.fromDict({ ...good, deny_list: [upper] }).denyList]).toEqual([lower]);
    // two spellings of one address are not `uniqueItems` duplicates -- the schema compares the
    // strings as given -- but they collapse once canonicalised, as the reference's frozenset does
    expect(Policy.fromDict({ ...good, deny_list: [upper, lower] }).denyList.size).toBe(1);
    // a non-EVM address form is left exactly as given (§2.1: other chains define their own)
    expect(canonicalAddress("SoLaNaLikeAddress")).toBe("SoLaNaLikeAddress");
    expect(canonicalAddress("0X" + "AB".repeat(20))).toBe(lower); // 0X is still an EVM address
  });
});

describe("Policy range validation", () => {
  // Spec §2 and Policy.__post_init__: the reference bounds both amounts to uint128, window_secs to
  // [1, 30 days] and expiry to [1, 2^64-1], and documents those bounds. A policy reaches this
  // client from the node (`attach`, `refresh`), and the signer exists so that the enclave does not
  // take the node's word for the policy -- so an out-of-range figure from a hostile or broken node
  // has to be refused here, not just rejected by the node that sent it.
  const cases: [string, () => unknown, RegExp][] = [
    ["per_tx_max below zero", () => new Policy(-1n, 100n, 60n), /per_tx_max must be an integer in \[0, 2\^128\)/],
    ["per_tx_max at 2^128", () => new Policy(2n ** 128n, 100n, 60n), /per_tx_max must be an integer in \[0, 2\^128\)/],
    ["per_window_max below zero", () => new Policy(1n, -1n, 60n), /per_window_max must be an integer in \[0, 2\^128\)/],
    ["per_window_max at 2^128", () => new Policy(1n, 2n ** 128n, 60n), /per_window_max must be an integer in \[0, 2\^128\)/],
    ["window_secs of zero", () => new Policy(1n, 1n, 0n), /window_secs must be in \[1, 2592000\]/],
    ["window_secs past 30 days", () => new Policy(1n, 1n, 2592001n), /window_secs must be in \[1, 2592000\]/],
    ["expiry of zero", () => new Policy(1n, 1n, 60n, null, new Set(), 0n), /\[1, 2\^64\)/],
    ["expiry at 2^64", () => new Policy(1n, 1n, 60n, null, new Set(), 2n ** 64n), /\[1, 2\^64\)/],
  ];

  it.each(cases)("the constructor refuses %s", (_name, build, match) => {
    expect(build).toThrow(PolicyViolation);
    expect(build).toThrow(match);
  });

  it("refuses the same figures arriving from the node", () => {
    // every path a policy can enter, not only the public constructor: this is the shape
    // `Agent.attach` and `refresh` hand to `Policy.fromDict`
    expect(() => Policy.fromDict({ ...good, window_secs: 0n })).toThrow(/window_secs must be in \[1, 2592000\]/);
    expect(() => Policy.fromDict({ ...good, per_window_max: 2n ** 128n })).toThrow(/\[0, 2\^128\)/);
  });

  it("admits the bounds themselves", () => {
    const p = new Policy(0n, 2n ** 128n - 1n, 2592000n, null, new Set(), 2n ** 64n - 1n);
    expect(p.perWindowMax).toBe(2n ** 128n - 1n);
    expect(p.windowSecs).toBe(2592000n);
    expect(p.expiry).toBe(2n ** 64n - 1n);
    expect(new Policy(0n, 0n, 1n).windowSecs).toBe(1n); // policy-007: zero caps, one-second window
  });

  it("shows why a window_secs of zero is a fail-open and not a nuisance", () => {
    // SpendWindow.spent prunes with `t > now - windowSecs`, so at zero every entry is dropped the
    // instant it is recorded: spentInWindow is always 0 and per_window_max stops existing in the
    // signer. The AgentSigner is there so the enclave does not take the node's word for the
    // policy, so a node serving `window_secs: 0` was switching off the cap it is checked against.
    const payee = "0x" + "aa".repeat(20);
    const kp = KeyPair.fromSeed("signer");
    const body = { op: "transfer" };

    const open = new AgentSigner(kp, new Policy(10n, 10n, 1n), "acct");
    open.policy.windowSecs = 0n; // the state the node could put the signer in; no longer reachable
    open.signPayment(payee, 10n, 1000n, body);
    open.signPayment(payee, 10n, 1000n, body); // 20 signed against a per-window cap of 10

    const sound = new AgentSigner(kp, new Policy(10n, 10n, 1n), "acct");
    sound.signPayment(payee, 10n, 1000n, body);
    expect(() => sound.signPayment(payee, 10n, 1000n, body)).toThrow(/per_window_max 10/);
    // and the figure cannot arrive from the wire any more
    expect(() => Policy.fromDict({ ...good, window_secs: 0n })).toThrow(PolicyViolation);
  });

  it("refuses a non-integer type for any of the four", () => {
    expect(() => new Policy(1 as never, 1n, 60n)).toThrow(/per_tx_max must be a bigint, not a number/);
    expect(() => new Policy(1n, 1n, 60 as never)).toThrow(/window_secs must be a bigint, not a number/);
    expect(() => new Policy(1n, 1n, 60n, null, new Set(), 1 as never)).toThrow(/expiry must be a bigint, not a number/);
    expect(() => new Policy(1n, 1n, "60" as never)).toThrow(/window_secs must be a bigint, not string/);
  });
});
