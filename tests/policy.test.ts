/**
 * Policy.fromDict refuses a field it does not implement.
 *
 * The rule and the message match `_reject_unknown` in foliant/accounts.py: the node answers 400
 * with that text, LedgerNode.call turns it back into a PolicyViolation, and a policy the Python
 * reference rejects must not be one this client quietly accepts.
 */
import { describe, expect, it } from "vitest";
import { Policy, PolicyViolation } from "../src/agent.js";

const good = {
  per_tx_max: 10, per_window_max: 100, window_secs: 60,
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
    expect(() => Policy.fromDict({ ...good, expiry: 2 ** 64 } as never)).toThrow(/\[1, 2\^64\)/);
    expect(() => Policy.fromDict({ ...good, expiry: 0 } as never)).toThrow(/\[1, 2\^64\)/);
    expect(Policy.fromDict({ ...good, expiry: 1 }).expiry).toBe(1);
  });

  it("refuses a non-object", () => {
    for (const bad of ["abc", 7, null, [good]]) {
      expect(() => Policy.fromDict(bad as never)).toThrow(/policy must be an object, not/);
    }
  });
});
