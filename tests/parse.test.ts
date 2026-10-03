/**
 * `parseJsonBig`: what it reads exactly, what it refuses, and what the fallback does.
 *
 * The unsupported-runtime branch is the half no test could reach before, because the runtime probe
 * was a module-level const evaluated at import. It is injectable now (`parseJsonBig(text, false)`).
 *
 * 0.1.x tried to serve that runtime with `/(?<![\w.])-?\d{16,}(?![\d.eE])/` over the raw document,
 * which was wrong in both directions: it refused documents that lose nothing, including about one
 * ordinary account response in 740 on the ids alone, and admitted `1e30` and `1e400`, which do not
 * survive. The tables below are kept because they are the evidence for both directions; what they
 * assert now is that the runtime is refused outright rather than served inexactly.
 */
import { describe, expect, it } from "vitest";
import { SOURCE_ACCESS, parseJsonBig } from "../src/crypto.js";

// What the old regex refused although nothing is lost. The first two are not numbers at all.
const LOSSLESS: [string, string][] = [
  ["a 16-digit run inside a string", '{"id":"1234567890123456"}'],
  ["a 16-digit object key", '{"1234567890123456":1}'],
  ["a 16-digit integer below 2^53", '{"a":1000000000000000}'],
  ["2^53 - 1 exactly", '{"a":9007199254740991}'],
  ["a long digit run after an escaped quote", '{"a":"say \\"1234567890123456789\\" twice","b":1}'],
  ["a negative 16-digit integer below 2^53", '{"a":-1000000000000000}'],
];

// Plain integers `JSON.parse` would round: read exactly on the exact path, refused on the fallback.
// The second is the direction a digit-count test gets wrong going the other way -- 16 digits, and
// one too many for a double.
const BEYOND_DOUBLE: [string, string][] = [
  ["a 19-digit integer", '{"a":1234567890123456789}'],
  ["2^53 + 1, which is 16 digits", '{"a":9007199254740993}'],
  ["a negative 19-digit integer", '{"a":-1234567890123456789}'],
];

// Integers written in a form neither path can read exactly. These are what the old digit-run test
// admitted and should not have: it cannot see an exponent at all.
const UNREADABLE: [string, string][] = [
  ["20 digits with a zero exponent", '{"a":12345678901234567890e0}'],
  ["1e30", '{"a":1e30}'],
  ["an integer written as 1.0", '{"a":1.0}'],
  // `Number.isInteger(Infinity)` is false, so an overflow literal slips past an integrality test
  // and comes back as Infinity -- which compares false against every bigint, and so walks straight
  // through the deposit guard in `Agent.payChannel`. It has to be named separately.
  ["1e400, which overflows to Infinity", '{"a":1e400}'],
  ["-1e400", '{"a":-1e400}'],
  ["1e309, just past the double range", '{"a":1e309}'],
];

describe("parseJsonBig on this runtime", () => {
  it("has the exact path available (Node 22 or later, as `engines` requires)", () => {
    expect(SOURCE_ACCESS).toBe(true);
  });

  it("reads every integer as a bigint, at every magnitude", () => {
    const o = parseJsonBig('{"small":1,"zero":0,"neg":-5,"big":123456789012345678901}') as any;
    expect(o.small).toBe(1n);
    expect(o.zero).toBe(0n);
    expect(o.neg).toBe(-5n);
    expect(o.big).toBe(123456789012345678901n);
  });

  it("leaves a genuine fraction alone", () => {
    // not a protocol value, and `canonical` refuses a number anyway, so there is nothing to carry
    expect((parseJsonBig('{"a":1.5}') as any).a).toBe(1.5);
  });

  it.each(BEYOND_DOUBLE)("reads %s exactly", (_name, doc) => {
    const got = (parseJsonBig(doc) as any).a;
    expect(typeof got).toBe("bigint");
    expect(String(got)).toBe(doc.slice(doc.indexOf(":") + 1, -1));
  });

  it.each(UNREADABLE)("refuses %s", (_name, doc) => {
    // Python's json.dumps writes an int as digits, so these did not come from the reference. And
    // they cannot be carried: `1e30` is not 10^30 as a double, and `1.0` would have to be
    // re-emitted as `1.0` to hash the way Python hashes it, which `canonical` cannot do from a
    // number. Refusing at the parse names the sender; the alternative is a figure that fails much
    // later, at a signature, with nothing to point at.
    expect(() => parseJsonBig(doc)).toThrow(/written as digits/);
  });
});

describe("parseJsonBig on a runtime without source access", () => {
  // There is no exact path there and no sound inexact one. A scan can say which literals
  // `JSON.parse` would misread, but the integers in a document it admitted would still come back
  // as `number`, which is not what this module's types promise -- so every document is refused,
  // not some. `engines: >=22` says the same thing to the installer.
  it.each([...LOSSLESS, ...BEYOND_DOUBLE, ...UNREADABLE])(
    "refuses %s, naming the runtime rather than the document",
    (_name, doc) => {
      expect(() => parseJsonBig(doc, false)).toThrow(/Node 22 or later is required/);
    },
  );

  it("refuses a document with no numbers in it at all", () => {
    // the point of refusing wholesale: the verdict does not depend on reading the document
    expect(() => parseJsonBig('{"a":"x"}', false)).toThrow(/Node 22 or later is required/);
  });
});
