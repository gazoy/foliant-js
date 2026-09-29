import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { KeyPair, PublicKey, Signed, canonical, hashObj, sign } from "../src/crypto.js";

const v = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));

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
      const tampered = new Signed({ ...s.body, balance: 999 }, PublicKey.fromDict(s.signer), s.signature);
      expect(tampered.valid()).toBe(false);
    }
  });
  it("computes the same policy id", () => {
    expect(hashObj(v.policy_id.policy)).toBe(v.policy_id.id);
  });
});
