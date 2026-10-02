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

  it("refuses a non-object", () => {
    for (const bad of ["abc", 7, null, [good]]) {
      expect(() => Policy.fromDict(bad as never)).toThrow(/policy must be an object, not/);
    }
  });
});
