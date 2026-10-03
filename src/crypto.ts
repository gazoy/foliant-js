/**
 * Keys, signatures and canonical hashing — byte-compatible with foliant/crypto.py.
 *
 * canonical(obj) = Python json.dumps(obj, sort_keys=True, separators=(",",":")),
 * which escapes non-ASCII as \uXXXX and has no whitespace. Every signed or
 * hashed message uses it, so a signature made here verifies on the ledger.
 */
import * as ed from "@noble/ed25519";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

// @noble/ed25519 v2 needs a sync sha512 for the sync API
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export const SCHEME = "ed25519";

/**
 * A public key reference from the wire is not one this implementation can use: wrong shape, not
 * lowercase hex, or the wrong length for its scheme. Mirrors `InvalidKey` in foliant/errors.py,
 * and exists for the same reason: every owner, signer and escalation co-signer key is parsed from
 * a document some other party wrote, so a bad one is a protocol rejection a caller can catch, not
 * a `TypeError` out of the hashing library.
 */
export class InvalidKey extends Error {}

export type Json = null | boolean | number | bigint | string | Json[] | { [k: string]: Json };

function escapeString(s: string): string {
  // Python's json.dumps default (ensure_ascii=True): escape control chars, quotes,
  // backslashes, and every non-ASCII code unit as \uXXXX (surrogate pairs as two escapes).
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const ch = s[i];
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (c < 0x20 || c > 0x7e) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

export function canonical(obj: Json): string {
  if (obj === null) return "null";
  if (typeof obj === "boolean") return obj ? "true" : "false";
  // Protocol integers are bigint: String(5n) is "5" at every magnitude, where String(1e21) is
  // "1e+21" and Python writes the digits. Emitting the digits is what makes a policy id and a
  // signed body identical in both implementations.
  if (typeof obj === "bigint") return String(obj);
  // No `number` is renderable here, whatever its magnitude. Python's json.dumps writes an int as
  // `1` and a float as `1.0` -- different bytes, so a different hash and a different signature --
  // and JavaScript has one numeric type in which `1` and `1.0` are the same value, so there is
  // nothing in a number to tell the two apart. A magnitude test cannot stand in for that: it
  // refuses 2**53, which Python agrees about, while admitting the one shape it disagrees about.
  // Above 2^53 the digits are gone as well, and above 1e21 String() writes `1e+21` where Python
  // writes digits. Protocol integers are bigint (README, "Amounts"), and parseJsonBig never hands
  // back a number for an integer literal, so a number on this path is a defect, not a value.
  if (typeof obj === "number") {
    throw new Error(
      `canonical: ${obj} is a number; pass a bigint ` +
        "(a number cannot be told apart from Python's 1.0, and above 2^53 it has already lost digits)",
    );
  }
  if (typeof obj === "string") return escapeString(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonical).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => escapeString(k) + ":" + canonical(obj[k])).join(",") + "}";
}

const INTEGER_LITERAL = /^-?\d+$/;

/** Whether this runtime gives a reviver the source text of each literal (Node 22 and later). */
export const SOURCE_ACCESS = (() => {
  try {
    let seen = false;
    JSON.parse("1", (_k, _v, ctx?: { source?: string }) => { seen = ctx?.source !== undefined; return _v; });
    return seen;
  } catch {
    return false;
  }
})();

function refuseInexact(src: string): never {
  throw new Error(
    `parseJsonBig: ${src} is not a plain-digit integer, so it cannot be carried exactly; ` +
      "protocol integers are written as digits",
  );
}

/**
 * JSON.parse that keeps every integer exactly, as a bigint.
 *
 * `JSON.parse('{"a":1234567890123456789}')` yields 1234567890123456768: the digits are gone before
 * any of this library sees the object, so no amount of care further in can recover them. The
 * reviver's `context.source` is the literal as it was written, which BigInt() reads exactly.
 *
 * Every integer becomes a bigint, not only the large ones. A parser that switched types by
 * magnitude would hand back a number here and a bigint there for the same field, and arithmetic
 * mixing the two throws at runtime in whichever deployment happened to see the bigger figure.
 *
 * A number literal that is not plain digits is refused rather than kept. Python's json.dumps
 * writes an int as plain digits, so such a literal did not come from the reference, and this
 * implementation cannot carry it: `1e30` is not 10^30 once it is a double, `1.0` would have to be
 * re-emitted as `1.0` to hash the way Python hashes it, and `1e400` is Infinity, which compares
 * false against every bigint and so silently defeats the deposit guard in `Agent.payChannel`.
 * Refusing at the parse names the sender; the alternative is a figure that fails later, at a
 * signature, with nothing to point at. A genuine fraction is left alone, because `canonical`
 * refuses it in turn and the error there is the clearer one.
 *
 * Node 22 or later is required (`engines`). On an older runtime there is no exact path and no
 * sound inexact one, so every document is refused rather than some: a scan can tell which literals
 * `JSON.parse` would misread, but the integers in a document it admitted would still come back as
 * `number`, which is not what this module's types promise. That is an unsupported runtime, not a
 * degraded mode.
 */
export function parseJsonBig(text: string, sourceAccess: boolean = SOURCE_ACCESS): Json {
  if (!sourceAccess) {
    throw new Error(
      "parseJsonBig: this runtime does not expose JSON literal source text, so integers cannot be " +
        "read exactly; Node 22 or later is required",
    );
  }
  return JSON.parse(text, function (_k, v, ctx?: { source?: string }) {
    const src = ctx?.source;
    if (src === undefined) return v; // an object or array, which has no literal of its own
    if (INTEGER_LITERAL.test(src)) return BigInt(src);
    // `Number.isInteger(Infinity)` is false, so the overflow case has to be named separately or
    // `1e400` comes back as Infinity and every `bigint > Infinity` comparison reads false.
    if (typeof v === "number" && (Number.isInteger(v) || !Number.isFinite(v))) refuseInexact(src);
    return v; // a genuine fraction: not a protocol value, and canonical() refuses it anyway
  }) as Json;
}

export function canonicalBytes(obj: Json): Uint8Array {
  return new TextEncoder().encode(canonical(obj));
}

export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(nobleSha256(data));
}

export function hashObj(obj: Json): string {
  return sha256Hex(canonicalBytes(obj));
}

export interface PublicKeyDict {
  scheme: string;
  key: string;
}

// Spec §2.2: a key reference is exactly {"scheme": <name>, "key": <lowercase hex>}, and the schema
// says the same ($defs.keyRef, additionalProperties false, pattern ^[0-9a-f]+$). Same rule, same
// messages, as KEYREF_FIELDS and PublicKey.from_dict in foliant/crypto.py.
const KEYREF_FIELDS: ReadonlySet<string> = new Set(["scheme", "key"]);
// Public key length per scheme, for the schemes this implementation knows. A scheme absent here
// still parses -- signature agility means an envelope can name a scheme we cannot verify, and
// `verify` is where that is refused -- but its length cannot be checked.
const KEY_BYTES: Readonly<Record<string, number>> = { [SCHEME]: 32 };
// Stricter than the schema in one way it cannot express: hex of odd length matches ^[0-9a-f]+$ but
// is not a whole number of bytes, so it is refused here rather than by hexToBytes with a RangeError.
const KEYREF_HEX = /^(?:[0-9a-f]{2})+$/;

export class PublicKey {
  constructor(public readonly scheme: string, public readonly raw: Uint8Array) {}

  get hex(): string {
    return bytesToHex(this.raw);
  }

  /** Address = first 20 bytes (40 hex chars) of sha256(scheme || pubkey). */
  get address(): string {
    const pre = new TextEncoder().encode(this.scheme);
    const buf = new Uint8Array(pre.length + this.raw.length);
    buf.set(pre);
    buf.set(this.raw, pre.length);
    return sha256Hex(buf).slice(0, 40);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    // an InvalidKey, not a bare Error: this is reachable from the wire (an envelope naming a
    // scheme this client does not implement), so it is a protocol rejection like any other
    if (this.scheme !== SCHEME) throw new InvalidKey(`unsupported scheme ${this.scheme}`);
    try {
      return ed.verify(signature, message, this.raw);
    } catch {
      return false;
    }
  }

  toDict(): PublicKeyDict {
    return { scheme: this.scheme, key: this.hex };
  }

  /**
   * Parse a key reference from the wire (spec §2.2).
   *
   * Every owner, signer and escalation co-signer key enters here, and this used to be
   * `new PublicKey(d.scheme, hexToBytes(d.key))`: bad hex and a missing `key` surfaced as a raw
   * TypeError or RangeError from inside @noble rather than as something a caller could catch, a
   * two-byte string was accepted as an ed25519 public key, and an unknown nested field was
   * dropped although the schema forbids it -- which, for a key inside a signed policy, meant the
   * id covered less than the signer wrote.
   */
  static fromDict(d: PublicKeyDict): PublicKey {
    if (typeof d !== "object" || d === null || Array.isArray(d)) {
      const got = d === null ? "null" : Array.isArray(d) ? "array" : typeof d;
      throw new InvalidKey(`key reference must be an object, not ${got}`);
    }
    const keys = new Set(Object.keys(d));
    // quote then sort, so each list reads the same as the Python reference's sorted repr()
    const unknown = [...keys].filter((k) => !KEYREF_FIELDS.has(k)).map((k) => `'${k}'`).sort();
    if (unknown.length) throw new InvalidKey(`unknown key reference field(s): ${unknown.join(", ")}`);
    const missing = [...KEYREF_FIELDS].filter((k) => !keys.has(k)).map((k) => `'${k}'`).sort();
    if (missing.length) throw new InvalidKey(`missing key reference field(s): ${missing.join(", ")}`);
    const { scheme, key } = d;
    if (typeof scheme !== "string" || !scheme) throw new InvalidKey("scheme must be a non-empty string");
    if (typeof key !== "string" || !KEYREF_HEX.test(key)) {
      throw new InvalidKey("key must be a non-empty even-length lowercase hex string");
    }
    const raw = hexToBytes(key);
    const want = KEY_BYTES[scheme];
    if (want !== undefined && raw.length !== want) {
      throw new InvalidKey(`a ${scheme} key is ${want} bytes, not ${raw.length}`);
    }
    return new PublicKey(scheme, raw);
  }
}

export class KeyPair {
  readonly public: PublicKey;

  private constructor(private readonly priv: Uint8Array) {
    this.public = new PublicKey(SCHEME, ed.getPublicKey(priv));
  }

  static generate(): KeyPair {
    return new KeyPair(ed.utils.randomPrivateKey());
  }

  /** Same derivation as Python: private key = sha256(seed). */
  static fromSeed(seed: Uint8Array | string): KeyPair {
    const s = typeof seed === "string" ? new TextEncoder().encode(seed) : seed;
    return new KeyPair(nobleSha256(s));
  }

  static fromPrivateHex(hex: string): KeyPair {
    return new KeyPair(hexToBytes(hex));
  }

  get privateHex(): string {
    return bytesToHex(this.priv);
  }

  get address(): string {
    return this.public.address;
  }

  sign(message: Uint8Array): Uint8Array {
    return ed.sign(message, this.priv);
  }

  signObj(obj: Json): string {
    return bytesToHex(this.sign(canonicalBytes(obj)));
  }
}

export interface SignedDict {
  body: { [k: string]: Json };
  signer: PublicKeyDict;
  signature: string;
}

export class Signed {
  constructor(
    public readonly body: { [k: string]: Json },
    public readonly signer: PublicKey,
    public readonly signature: string,
  ) {}

  valid(): boolean {
    return this.signer.verify(canonicalBytes(this.body), hexToBytes(this.signature));
  }

  toDict(): SignedDict {
    return { body: this.body, signer: this.signer.toDict(), signature: this.signature };
  }

  static fromDict(d: SignedDict): Signed {
    return new Signed(d.body, PublicKey.fromDict(d.signer), d.signature);
  }
}

export function sign(kp: KeyPair, body: { [k: string]: Json }): Signed {
  return new Signed(body, kp.public, kp.signObj(body));
}
