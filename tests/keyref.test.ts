/**
 * Key references from the wire: every owner, signer and escalation co-signer enters through
 * `PublicKey.fromDict`.
 *
 * It was `new PublicKey(d.scheme, hexToBytes(d.key))`. Bad hex and a missing `key` came out as a
 * raw TypeError or RangeError from inside @noble rather than as anything a caller could catch, an
 * unknown nested field was dropped although the schema forbids it, and a two-byte string was
 * accepted as an ed25519 public key. The last is the one that matters: an account could be left
 * holding a co-signer that cannot verify anything, so the owner believes an escalation path exists
 * where none does.
 *
 * The cases, and the messages, are those of tests/test_keyref.py in the Python reference.
 */
import { describe, expect, it } from "vitest";
import { InvalidKey, KeyPair, PublicKey, SCHEME } from "../src/crypto.js";
import { Policy, PolicyViolation } from "../src/agent.js";

const GOOD = KeyPair.fromSeed("co-signer").public;

describe("PublicKey.fromDict", () => {
  it.each([
    [{ scheme: SCHEME, key: "zz" }, /lowercase hex/],                 // was a TypeError out of @noble
    [{ scheme: SCHEME }, /missing key reference/],                    // was "cannot read length of undefined"
    [{ key: "ab".repeat(32) }, /missing key reference/],
    [{ scheme: SCHEME, key: "ab".repeat(32), extra: 1 }, /unknown key reference/], // schema forbids
    [{ scheme: SCHEME, key: "abcd" }, /is 32 bytes, not 2/],          // was accepted
    [{ scheme: SCHEME, key: "abc" }, /lowercase hex/],                // odd length is not bytes
    [{ scheme: SCHEME, key: "AB".repeat(32) }, /lowercase hex/],      // §2.2 says lowercase
    [{ scheme: SCHEME, key: "" }, /lowercase hex/],
    [{ scheme: SCHEME, key: 1 }, /lowercase hex/],
    [{ scheme: "", key: "ab".repeat(32) }, /non-empty string/],
    [{ scheme: 7, key: "ab".repeat(32) }, /non-empty string/],
  ])("refuses %j", (bad, match) => {
    expect(() => PublicKey.fromDict(bad as never)).toThrow(InvalidKey);
    expect(() => PublicKey.fromDict(bad as never)).toThrow(match);
  });

  it.each(["abc", 7, null, [{ scheme: SCHEME, key: "ab".repeat(32) }]])("refuses the non-object %j", (bad) => {
    expect(() => PublicKey.fromDict(bad as never)).toThrow(/must be an object/);
  });

  it("still round-trips a valid key reference", () => {
    const back = PublicKey.fromDict(GOOD.toDict());
    expect(back.hex).toBe(GOOD.hex);
    expect(back.scheme).toBe(SCHEME);
    expect(back.raw.length).toBe(32);
  });

  it("parses an unimplemented scheme but cannot verify with it", () => {
    // Signature agility (crypto.ts's header): an envelope may name a scheme this client does not
    // implement, so its length cannot be checked and it parses; `verify` is where it is refused.
    const other = PublicKey.fromDict({ scheme: "ed448", key: "ab".repeat(57) });
    expect(other.scheme).toBe("ed448");
    expect(() => other.verify(new Uint8Array(1), new Uint8Array(1))).toThrow(InvalidKey);
    expect(() => other.verify(new Uint8Array(1), new Uint8Array(1))).toThrow(/unsupported scheme ed448/);
  });

  it("reports a bad co-signer inside a policy as a policy violation", () => {
    // §2: an invalid policy is policy_invalid whichever part of it is invalid, so the key-level
    // reason is translated rather than leaking InvalidKey out of the policy loader.
    const base = new Policy(1n, 1n, 60n).toDict();
    const bad = { ...base, escalation: { scheme: SCHEME, key: "abcd" } };
    expect(() => Policy.fromDict(bad)).toThrow(PolicyViolation);
    expect(() => Policy.fromDict(bad)).toThrow(/escalation: a ed25519 key is 32 bytes/);
    // and an unknown field in the nested key reference, which used to vanish from the policy id
    expect(() => Policy.fromDict({ ...base, escalation: { scheme: SCHEME, key: GOOD.hex, extra: 1 } } as never))
      .toThrow(/escalation: unknown key reference field\(s\): 'extra'/);
  });
});
