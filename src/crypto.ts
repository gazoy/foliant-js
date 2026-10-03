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
  if (typeof obj === "number") {
    if (!Number.isInteger(obj)) throw new Error("canonical: only integers are supported");
    // A double above 2^53 has already lost digits by the time it reaches here, and above 1e21 it
    // renders in exponential form, which Python never writes. Either way the bytes would diverge
    // silently, so refuse rather than hash something the ledger will not recognise.
    if (!Number.isSafeInteger(obj)) {
      throw new Error(`canonical: ${obj} is outside the exact range of number; pass a bigint`);
    }
    return String(obj);
  }
  if (typeof obj === "string") return escapeString(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonical).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => escapeString(k) + ":" + canonical(obj[k])).join(",") + "}";
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
 */
const INTEGER_LITERAL = /^-?\d+$/;
const SOURCE_ACCESS = (() => {
  try {
    let seen = false;
    JSON.parse("1", (_k, _v, ctx?: { source?: string }) => { seen = ctx?.source !== undefined; return _v; });
    return seen;
  } catch {
    return false;
  }
})();

export function parseJsonBig(text: string): Json {
  if (SOURCE_ACCESS) {
    return JSON.parse(text, function (_k, v, ctx?: { source?: string }) {
      const src = ctx?.source;
      return src !== undefined && INTEGER_LITERAL.test(src) ? BigInt(src) : v;
    }) as Json;
  }
  // Older runtimes have no exact path. Refuse the documents that would lose digits rather than
  // return a rounded one: silence here is what the README calls the dangerous half.
  if (/(?<![\w.])-?\d{16,}(?![\d.eE])/.test(text)) {
    throw new Error("parseJsonBig: this runtime cannot parse integers of this size exactly; Node 22 or later is required");
  }
  return JSON.parse(text) as Json;
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
    if (this.scheme !== SCHEME) throw new Error(`unsupported scheme ${this.scheme}`);
    try {
      return ed.verify(signature, message, this.raw);
    } catch {
      return false;
    }
  }

  toDict(): PublicKeyDict {
    return { scheme: this.scheme, key: this.hex };
  }

  static fromDict(d: PublicKeyDict): PublicKey {
    return new PublicKey(d.scheme, hexToBytes(d.key));
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
