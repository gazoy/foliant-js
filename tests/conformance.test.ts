/**
 * The specification's own conformance vectors, run against this client.
 *
 * `docs/spec/vectors.json` in the reference repo is the test of agreement between implementations
 * (spending-policy.md, header), so it is better run than paraphrased. Two kinds are driven here:
 *
 * - `check`: §3 evaluation, including `check-030` and `check-031`, which give a payee and a deny
 *   entry in mixed case precisely because §2.1 requires both canonicalised. Both failed before
 *   this client canonicalised anything.
 * - `policy`: §2 validity, which is where the range bounds live.
 *
 * The vectors are in the specification's wire form (camelCase, amounts as decimal strings) and
 * this client parses the reference's envelope form, so `fromWire` below is the adapter. It is a
 * key rename and a `BigInt` call, not a second parser: the validity rules under test are the
 * constructor's.
 */
import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { Policy, PolicyViolation } from "../src/agent.js";

const REF = process.env.FOLIANT_REF ?? "/home/claude/concord";
const PATH = `${REF}/docs/spec/vectors.json`;
// Skipped rather than failed when the reference is not checked out: this suite is a cross-repo
// agreement check, and `npm run test:unit` (what `prepublishOnly` runs) has to pass on a release
// machine that has only this package.
const HAVE_REF = existsSync(PATH);
const vectors = HAVE_REF ? (JSON.parse(readFileSync(PATH, "utf8")).vectors as any[]) : [];

interface Wire {
  perTxMax: string; perWindowMax: string; windowSecs: number;
  allowList: string[] | null; denyList: string[]; expiry: number | null; escalation: unknown;
}

function fromWire(w: Wire): Policy {
  return Policy.fromDict({
    per_tx_max: BigInt(w.perTxMax),
    per_window_max: BigInt(w.perWindowMax),
    window_secs: BigInt(w.windowSecs),
    allow_list: w.allowList,
    deny_list: w.denyList,
    expiry: w.expiry === null ? null : BigInt(w.expiry),
    escalation: w.escalation as never,
  });
}

// §3's reason codes against the messages `Policy.check` raises. The Python PolicyViolation carries
// the code itself; this client's does not, so the mapping lives here rather than in the library.
const CODES: [RegExp, string][] = [
  [/^negative amount$/, "negative_amount"],
  [/^policy expired$/, "expired"],
  [/ is denied$/, "payee_denied"],
  [/ is not on the allow list$/, "payee_not_allowed"],
  [/ exceeds per_tx_max /, "per_tx_exceeded"],
  [/ would exceed per_window_max /, "per_window_exceeded"],
];

function reason(e: unknown): string {
  const m = (e as Error).message;
  for (const [re, code] of CODES) if (re.test(m)) return code;
  throw new Error(`no §3 reason code for: ${m}`);
}

const checks = vectors.filter((v) => v.kind === "check");
const policies = vectors.filter((v) => v.kind === "policy");

// The two amount-grammar vectors ("1_000" and "01") test the wire form's decimal-string grammar,
// which this client never sees: it reads the envelope form, where amounts are already integers.
const GRAMMAR_ONLY = new Set(["policy-004", "policy-005"]);

describe.skipIf(!HAVE_REF)("spending-policy.md conformance vectors", () => {
  it("has found the reference's vectors", () => {
    expect(checks.length).toBeGreaterThan(20);
    expect(policies.length).toBeGreaterThan(5);
  });

  it.each(checks.map((v) => [v.id, v] as const))("%s", (_id, v) => {
    const p = fromWire(v.policy);
    const run = () => p.check(BigInt(v.amount), v.payee, BigInt(v.now), BigInt(v.spentInWindow), v.escalated);
    if (v.expect === "ok") {
      expect(run).not.toThrow();
    } else {
      let caught: unknown = null;
      try { run(); } catch (e) { caught = e; }
      expect(caught).toBeInstanceOf(PolicyViolation);
      expect(reason(caught)).toBe(v.expect);
    }
  });

  it.each(policies.filter((v) => !GRAMMAR_ONLY.has(v.id)).map((v) => [v.id, v] as const))("%s", (_id, v) => {
    if (v.expect === "ok") {
      expect(() => fromWire(v.policy)).not.toThrow();
    } else {
      expect(() => fromWire(v.policy)).toThrow(PolicyViolation);
    }
  });

  it("gives a mixed-case policy the same id as its canonical twin", () => {
    // Not an `id` vector: those hash the §2.2 wire encoding, which this client does not produce
    // (`Policy.id` hashes the envelope form, as the reference's own `Policy.id` does). The
    // property the vectors are really asserting — that case is not part of a policy's identity —
    // is testable without it, and it is the property `Agent.register` depends on.
    const mixed = vectors.find((v) => v.id === "id-004").policy as Wire;
    const lower = {
      ...mixed,
      allowList: mixed.allowList!.map((a) => a.toLowerCase()),
      escalation: (mixed.escalation as string).toLowerCase(),
    };
    expect(fromWire(mixed).id).toBe(fromWire(lower).id);
    expect(fromWire(mixed).escalation).toBe(lower.escalation);
  });
});
