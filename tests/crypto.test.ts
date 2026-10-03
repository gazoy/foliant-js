import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { KeyPair, PublicKey, Signed, canonical, hashObj, parseJsonBig, sign } from "../src/crypto.js";

// parseJsonBig, not JSON.parse: these vectors predate the bigint migration, so their protocol
// integers are written as plain digits and JSON.parse hands them back as `number`s, which
// `canonical` now refuses outright -- it cannot tell such a value from Python's `1.0`, which
// serialises to different bytes. Reading them the way the library reads the node's own responses
// is what makes the comparison with Python's bytes meaningful rather than a comparison with
// JavaScript's idea of a number.
const v = parseJsonBig(readFileSync(new URL("./vectors.json", import.meta.url), "utf8")) as any;

describe("byte-compatibility with foliant/crypto.py", () => {
  it("derives the same keys and addresses from seeds", () => {
    for (const s of v.seeds) {
      const kp = KeyPair.fromSeed(s.seed);
      expect(kp.public.hex).toBe(s.pub);
      expect(kp.address).toBe(s.address);
    }
  });
  it("produces identical canonical bytes and hashes, including unicode and nesting", () => {
    for (const c of v.canonical) {
      expect(canonical(c.obj)).toBe(c.bytes);
      expect(hashObj(c.obj)).toBe(c.hash);
    }
  });
  it("produces signatures Python made, and verifies Python's", () => {
    const kp = KeyPair.fromSeed("alice");
    for (const s of v.signed) {
      const mine = sign(kp, s.body);
      expect(mine.signature).toBe(s.signature); // Ed25519 is deterministic
      expect(Signed.fromDict(s).valid()).toBe(true);
      const tampered = new Signed({ ...s.body, balance: 999n }, PublicKey.fromDict(s.signer), s.signature);
      expect(tampered.valid()).toBe(false);
    }
  });
  it("computes the same policy id", () => {
    expect(hashObj(v.policy_id.policy)).toBe(v.policy_id.id);
  });
});
