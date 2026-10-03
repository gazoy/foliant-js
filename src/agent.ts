/**
 * Foliant client against a ledger node (foliant/node.py) — the agent side of
 * foliant/agent.py and foliant/x402.py, in TypeScript.
 *
 * The signer enforces the account's own policy before signing anything, as the
 * Python AgentSigner does; the ledger enforces it again, and every ancestor's,
 * when a deposit is applied. Off-chain updates are bounded by the deposit they
 * draw on.
 */
import {
  canonical, hashObj, InvalidKey, Json, KeyPair, parseJsonBig, PublicKey, PublicKeyDict, sign, Signed, SignedDict,
} from "./crypto.js";

export interface PolicyDict {
  per_tx_max: bigint;
  per_window_max: bigint;
  window_secs: bigint;
  allow_list: string[] | null;
  deny_list: string[];
  expiry: bigint | null;
  // Spec §2: a key reference, an address string, or null. The address form is what makes this a
  // union: a Python node accepts and stores one, so a client typed for the object form alone
  // could not attach to such an account at all.
  escalation: PublicKeyDict | string | null;
}

export class PolicyViolation extends Error {}

// Spec §2/§2.2: a policy has exactly these seven fields (the schema sets "additionalProperties":
// false, and so does $defs.keyRef). A loader that dropped a field it did not understand would
// enforce less than the owner signed over, because `id` is computed from `toDict()` and so covers
// only the fields that survived. Same rule, and the same message, as `_reject_unknown` in
// foliant/accounts.py -- the two implementations have to agree on which policies are valid, or a
// crew spanning both gets different budget semantics depending on which SDK parsed last.
const DICT_FIELDS: ReadonlySet<string> = new Set([
  "per_tx_max", "per_window_max", "window_secs", "allow_list", "deny_list", "expiry", "escalation",
]);

// The schema's expiry maximum is 2**64 - 1. As a bigint that bound is exact and can be written
// as the schema writes it; the earlier code tested against an exclusive 2**64 because no double
// represents 2**64 - 1 and the rounding would otherwise have admitted it.
const EXPIRY_MAX = 2n ** 64n - 1n;
// The other two bounds `Policy.__post_init__` applies, with the same values and for the same
// reasons: spec §2 lets an implementation bound amounts and `windowSecs` provided it documents the
// bound and rejects rather than truncates, and the Python reference bounds them to these.
const UINT128_MAX = 2n ** 128n - 1n;
const MAX_WINDOW_SECS = 30n * 86400n;
const ZERO_ADDRESS = "0x" + "0".repeat(40);

/**
 * TypeScript rejects an excess property on an object *literal* typed as PolicyDict, but not on a
 * variable and not on anything that came back from JSON.parse -- which is every policy this client
 * actually sees. So the check has to exist at runtime.
 */
function checkFields(d: unknown, allowed: ReadonlySet<string>): void {
  if (typeof d !== "object" || d === null || Array.isArray(d)) {
    const got = d === null ? "null" : Array.isArray(d) ? "array" : typeof d;
    throw new PolicyViolation(`policy must be an object, not ${got}`);
  }
  // quote then sort, so each list reads the same as the Python reference's sorted repr()
  const keys = new Set(Object.keys(d));
  const unknown = [...keys].filter((k) => !allowed.has(k)).map((k) => `'${k}'`).sort();
  if (unknown.length) throw new PolicyViolation(`unknown policy field(s): ${unknown.join(", ")}`);
  // A missing field is the more dangerous half: the defaults below are the permissive readings,
  // and register() signs the id of what this client parsed, so a field left out of the dict
  // widens what the owner signed and the node accepts it -- toDict() sends all seven either way.
  const missing = [...allowed].filter((k) => !keys.has(k)).map((k) => `'${k}'`).sort();
  if (missing.length) throw new PolicyViolation(`missing policy field(s): ${missing.join(", ")}`);
}

/**
 * The type guard every integer field shares. Deliberately not coercing: a number reaching here is
 * either already rounded or about to be, and accepting the small ones would hide the defect until
 * the first large one.
 */
function integerField(v: unknown, name: string): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    throw new PolicyViolation(`${name} must be a bigint, not a number: a number holds integers exactly only below 2^53`);
  }
  throw new PolicyViolation(`${name} must be a bigint, not ${v === null ? "null" : typeof v}`);
}

/**
 * `per_tx_max` / `per_window_max`: a uint128, as `Policy.__post_init__` bounds them.
 *
 * The range is checked here and not only at construction sites, because a policy arrives from the
 * node (`Agent.attach`, `refresh`) as well as from local code, and the signer exists precisely so
 * that the enclave does not take the node's word for the policy it is enforcing.
 */
function amount(v: unknown, name: string): bigint {
  const n = integerField(v, name);
  if (n < 0n || n > UINT128_MAX) throw new PolicyViolation(`${name} must be an integer in [0, 2^128)`);
  return n;
}

/**
 * `window_secs`: at least 1, at most the reference's 30 days.
 *
 * Zero is the dangerous end, and it is a fail-open rather than a nuisance: `SpendWindow.spent`
 * takes `cutoff = now - windowSecs` and keeps entries with `t > cutoff`, so at 0 every entry is
 * pruned the instant it is recorded, `spentInWindow` is always 0 and `per_window_max` stops
 * existing in the signer. A node serving `window_secs: 0` would disable the cap it was supposed
 * to be checked against.
 */
function windowSecsField(v: unknown): bigint {
  const n = integerField(v, "window_secs");
  if (n < 1n || n > MAX_WINDOW_SECS) throw new PolicyViolation(`window_secs must be in [1, ${MAX_WINDOW_SECS}]`);
  return n;
}

/** `expiry`: null, or a uint64 of at least 1. Wire-form 0 is invalid (spec §2). */
function expiryField(v: unknown): bigint | null {
  if (v === null) return null;
  const n = integerField(v, "expiry");
  if (n < 1n || n > EXPIRY_MAX) throw new PolicyViolation("expiry must be null or an integer in [1, 2^64)");
  return n;
}

/**
 * Spec §2 and `_escalation` in foliant/accounts.py: the co-signer is a keyRef object, an address
 * string, or null. The address form is not a curiosity -- a Python node accepts and stores one --
 * and calling `PublicKey.fromDict` on it unconditionally made `Agent.attach` to such an account
 * throw a raw TypeError out of @noble, from a policy the node considered perfectly valid.
 */
function escalationField(v: unknown): PublicKey | string | null {
  if (!v) return null; // Python's `esc or None`: null, and anything else falsy, is no co-signer
  if (typeof v === "string") return v; // canonicalised with the lists, in the constructor
  if (typeof v === "object" && !Array.isArray(v)) {
    try {
      return PublicKey.fromDict(v as PublicKeyDict);
    } catch (e) {
      // §2: an invalid policy reports policy_invalid whichever part of it is invalid, so the
      // key-level reason travels in the message rather than as InvalidKey, as `_escalation` does
      if (e instanceof InvalidKey) throw new PolicyViolation(`escalation: ${e.message}`);
      throw e;
    }
  }
  // One narrowing against the reference, which returns any truthy non-dict value unchanged: a
  // number or a boolean would survive there as the co-signer, where it can only ever fail the
  // ledger's signer comparison. The schema admits exactly null, an address and a keyRef, so
  // refusing the rest cannot refuse a policy a conformant node could have meant anything by.
  throw new PolicyViolation(`escalation must be a key reference, an address string, or null, not ${typeof v}`);
}

/** Spec §2.1: EVM addresses compare in lowercase hex; other address forms as given. */
export function canonicalAddress(a: string): string {
  if (typeof a !== "string") {
    throw new PolicyViolation(`address must be a string, not ${a === null ? "null" : typeof a}`);
  }
  return a.startsWith("0x") || a.startsWith("0X") ? a.toLowerCase() : a;
}

/**
 * Spec §2.1 and the schema's `uniqueItems`: an address list is a list of distinct strings. A bare
 * string would otherwise become a Set of single characters, and duplicates would be deduplicated
 * where the schema forbids them. Two spellings of one EVM address are not duplicates here -- the
 * schema's `uniqueItems` compares the strings as given -- but they do collapse a moment later,
 * because §2.1 defines addresses to compare in lowercase and the constructor canonicalises every
 * entry, exactly as `Policy.__post_init__` does.
 */
function addrList(v: unknown, name: string): Set<string> {
  if (!Array.isArray(v)) {
    throw new PolicyViolation(`${name} must be a list, not ${v === null ? "null" : typeof v}`);
  }
  for (const a of v) {
    if (typeof a !== "string") throw new PolicyViolation(`${name} entries must be strings, not ${typeof a}`);
  }
  const set = new Set<string>(v);
  if (set.size !== v.length) throw new PolicyViolation(`${name} has duplicate entries`);
  return set;
}

export class Policy {
  constructor(
    public perTxMax: bigint,
    public perWindowMax: bigint,
    public windowSecs: bigint,
    public allowList: Set<string> | null = null,
    public denyList: Set<string> = new Set(),
    public expiry: bigint | null = null,
    public escalation: PublicKey | string | null = null,
  ) {
    // Everything `Policy.__post_init__` does, and here for the same reason it is there rather than
    // in `from_dict`: this is the one gate every policy passes through, whether it was written by
    // the caller, parsed from the node's account view, or rebuilt by `toDict`/`fromDict` on every
    // refresh. Validation only in `fromDict` left the public constructor checking nothing at all.
    this.perTxMax = amount(perTxMax, "per_tx_max");
    this.perWindowMax = amount(perWindowMax, "per_window_max");
    this.windowSecs = windowSecsField(windowSecs);
    this.expiry = expiryField(expiry);
    // Canonicalise the lists (spec §2.1). Without this a mixed-case policy hashes to a different
    // id than the node's, so `Agent.register` fails with "registration body does not match
    // parameters"; a deny entry in the wrong case never matches a payee; and an allow entry in the
    // wrong case can never be paid. Two spellings of one address collapse into one, as they do in
    // the reference's frozenset comprehension.
    if (this.allowList !== null) this.allowList = new Set([...this.allowList].map(canonicalAddress));
    this.denyList = new Set([...this.denyList].map(canonicalAddress));
    if (typeof this.escalation === "string") {
      this.escalation = canonicalAddress(this.escalation);
      // §2: the all-zero address is invalid for the same reason `expiry` 0 is -- a binary encoding
      // may use it for "none" internally, so a wire-form one must be rejected, not passed through
      if (this.escalation === ZERO_ADDRESS) throw new PolicyViolation("escalation must not be the zero address");
    }
  }

  toDict(): PolicyDict {
    return {
      per_tx_max: this.perTxMax,
      per_window_max: this.perWindowMax,
      window_secs: this.windowSecs,
      allow_list: this.allowList ? [...this.allowList].sort() : null,
      deny_list: [...this.denyList].sort(),
      expiry: this.expiry,
      // an address-form co-signer stays a string, as it does in the reference's `to_dict`;
      // assuming a PublicKey is what made `id` throw on one
      escalation: this.escalation instanceof PublicKey ? this.escalation.toDict() : this.escalation,
    };
  }

  static fromDict(d: PolicyDict): Policy {
    checkFields(d, DICT_FIELDS);
    // The field types and ranges are the constructor's job (as `__post_init__` is the dataclass's),
    // so this only has to turn the wire shapes into the constructor's: lists into Sets, the
    // escalation union into a PublicKey or an address.
    return new Policy(
      d.per_tx_max, d.per_window_max, d.window_secs,
      d.allow_list === null ? null : addrList(d.allow_list, "allow_list"),
      addrList(d.deny_list, "deny_list"), d.expiry,
      escalationField(d.escalation),
    );
  }

  get id(): string {
    return hashObj(this.toDict() as unknown as Json);
  }

  /** Same checks, same order, same messages as Policy.check in Python. */
  check(amount: bigint, payee: string, now: bigint, spentInWindow: bigint, escalated = false): void {
    // Spec §2.1 requires the payee canonicalised at evaluation, as the lists are at load; vectors
    // check-030 and check-031 are a mixed-case payee against a lowercase allow list and the
    // reverse. The node stores whatever case the channel was opened with, so without this a
    // deny-listed provider keeps getting updates signed.
    payee = canonicalAddress(payee);
    if (amount < 0n) throw new PolicyViolation("negative amount");
    if (this.expiry !== null && now >= this.expiry) throw new PolicyViolation("policy expired");
    if (this.denyList.has(payee)) throw new PolicyViolation(`payee ${payee} is denied`);
    if (this.allowList !== null && !this.allowList.has(payee)) throw new PolicyViolation(`payee ${payee} is not on the allow list`);
    if (amount > this.perTxMax && !escalated) throw new PolicyViolation(`amount ${amount} exceeds per_tx_max ${this.perTxMax}`);
    if (spentInWindow + amount > this.perWindowMax) {
      throw new PolicyViolation(`amount ${amount} would exceed per_window_max ${this.perWindowMax} (already spent ${spentInWindow})`);
    }
  }
}

class SpendWindow {
  entries: [bigint, bigint][] = [];
  spent(now: bigint, windowSecs: bigint): bigint {
    const cutoff = now - windowSecs;
    this.entries = this.entries.filter(([t]) => t > cutoff);
    return this.entries.reduce((a, [, v]) => a + v, 0n);
  }
  record(now: bigint, amount: bigint): void {
    this.entries.push([now, amount]);
  }
}

/** The enclave side: holds the signer key and refuses to sign outside policy. */
export class AgentSigner {
  readonly window = new SpendWindow();
  private lastBalance = new Map<string, bigint>();

  constructor(public readonly keypair: KeyPair, public policy: Policy, public readonly accountId: string) {}

  signPayment(payee: string, amount: bigint, now: bigint, body: { [k: string]: Json }, escalated = false): Signed {
    const spent = this.window.spent(now, this.policy.windowSecs);
    this.policy.check(amount, payee, now, spent, escalated);
    this.window.record(now, amount);
    return sign(this.keypair, body);
  }

  signUpdate(kind: "channel" | "pool", objId: string, payee: string, seq: bigint, balance: bigint, now: bigint, epoch?: bigint): Signed {
    const last = this.lastBalance.get(objId) ?? 0n;
    if (balance < last) throw new PolicyViolation("balance must not decrease");
    const spent = this.window.spent(now, this.policy.windowSecs);
    this.policy.check(0n, payee, now, spent);
    const body: { [k: string]: Json } = { kind, id: objId, seq, balance, account: this.accountId };
    if (epoch !== undefined) body.epoch = epoch; // pool claims: which membership this update belongs to
    const s = sign(this.keypair, body);
    this.lastBalance.set(objId, balance);
    return s;
  }

  /** Drop the monotonic-balance record for a closed channel or exited pool claim. */
  forget(objId: string): void {
    this.lastBalance.delete(objId);
  }

  signPlain(body: { [k: string]: Json }): Signed {
    return sign(this.keypair, body);
  }

  rollback(snapshot: [bigint, bigint][]): void {
    this.window.entries = snapshot;
  }
}

// Every integer the node sends arrives as a bigint (parseJsonBig), including the counters and
// timestamps. Keeping one numeric type across the whole protocol surface means no call site has
// to remember which fields are safe to mix: bigint arithmetic refuses a stray number outright
// rather than silently widening it to a double.
export interface AccountView {
  id: string;
  address: string;
  owner: { scheme: string; key: string };
  signer: { scheme: string; key: string };
  policy: PolicyDict;
  nonce: bigint;
  parent: string | null;
  spent_in_window: bigint;
  balances: Record<string, bigint>;
}

export interface ChannelView {
  id: string; payer_account: string; payee: string; asset: string; deposit: bigint;
  balance_to_payee: bigint; seq: bigint; timeout_secs: bigint; closing_at: bigint | null; closed: boolean;
}

export interface PoolView {
  id: string; coordinator: string; asset: string; timeout_secs: bigint;
  members: Record<string, { deposit: bigint; paid: bigint; seq: bigint; exit_at: bigint | null; exited: boolean; epoch: bigint }>;
}

export class LedgerError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
  }
}

/** Thin HTTP client for the ledger node. `fetchFn` defaults to globalThis.fetch. */
export class LedgerNode {
  constructor(public readonly baseUrl: string, private readonly fetchFn: typeof fetch = globalThis.fetch.bind(globalThis)) {}

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const r = await this.fetchFn(this.baseUrl + path, {
      method,
      headers: body ? { "content-type": "application/json" } : undefined,
      // canonical(), not JSON.stringify(): the latter throws on a bigint, and the former already
      // writes the digits in the form the ledger hashes. Key order is irrelevant to the node.
      body: body ? canonical(body as Json) : undefined,
    });
    if (!r.ok) {
      let detail = await r.text();
      try {
        detail = JSON.parse(detail).detail ?? detail;
      } catch { /* plain text */ }
      if (r.status === 400 && String(detail).startsWith("PolicyViolation")) throw new PolicyViolation(String(detail).replace(/^PolicyViolation: /, ""));
      throw new LedgerError(String(detail), r.status);
    }
    // r.json() would round every integer above 2^53 before this library ever saw it
    return parseJsonBig(await r.text()) as T;
  }

  now(): Promise<{ now: bigint }> { return this.call("GET", "/ledger/now"); }
  account(id: string): Promise<AccountView> { return this.call("GET", `/ledger/accounts/${id}`); }
  channel(id: string): Promise<ChannelView> { return this.call("GET", `/ledger/channels/${id}`); }
  pool(id: string): Promise<PoolView> { return this.call("GET", `/ledger/pools/${id}`); }
  balance(address: string, asset: string): Promise<{ balance: bigint }> { return this.call("GET", `/ledger/balances/${address}/${asset}`); }
  faucet(address: string, asset: string, amount: bigint): Promise<{ balance: bigint }> {
    return this.call("POST", "/ledger/faucet", { address, asset, amount });
  }
  register(ownerSigned: SignedDict, signer: { scheme: string; key: string }, policy: PolicyDict, salt: bigint = 0n): Promise<AccountView> {
    return this.call("POST", "/ledger/accounts", { owner_signed: ownerSigned, signer, policy, salt });
  }
  tx(envelope: SignedDict, escalation?: SignedDict): Promise<{ result: Record<string, Json> }> {
    return this.call("POST", "/ledger/tx", { envelope, escalation: escalation ?? null });
  }
}

/**
 * Read a bigint field out of a node's view, refusing anything else.
 *
 * `LedgerNode.call` ends in `parseJsonBig(...) as T`: the cast is an assertion about a document the
 * node wrote, not a check. That matters most at the deposit guards below, which are the only bound
 * an off-chain update has (spec §7.1 -- the deposit is the spend, already checked against the
 * policy when the channel was opened). Every one of `balance > ch.deposit`, `balance > undefined`
 * and `balance > {}` evaluates to false, so a node that omits the field, or sends it as a string
 * or an object, gets an update signed for any amount at all. Compare nothing that was not read as
 * a bigint.
 */
function fromNode(view: Record<string, unknown>, field: string, what: string): bigint {
  const v = view[field];
  if (typeof v !== "bigint") {
    throw new LedgerError(`${what}: ${field} is ${v === undefined ? "missing" : `not an integer (${typeof v})`}`, 0);
  }
  return v;
}

/** An agent: one account on the node, operated by a signer under a policy. */
export class Agent {
  readonly latest = new Map<string, Signed>();
  private channelSeq = new Map<string, bigint>();
  private poolSeq = new Map<string, bigint>();

  private constructor(
    public readonly node: LedgerNode,
    public readonly owner: KeyPair | null,
    public readonly signer: AgentSigner,
    public account: AccountView,
  ) {}

  /** Register a new account: the owner signs the registration, the signer operates it. */
  static async register(node: LedgerNode, owner: KeyPair, signerKp: KeyPair, policy: Policy, salt: bigint = 0n): Promise<Agent> {
    const reg = sign(owner, { op: "register", signer: { ...signerKp.public.toDict() }, policy_id: policy.id, salt });
    const view = await node.register(reg.toDict(), signerKp.public.toDict(), policy.toDict(), salt);
    return new Agent(node, owner, new AgentSigner(signerKp, policy, view.id), view);
  }

  /** Attach to an account that already exists (for example one delegated by an orchestrator). */
  static async attach(node: LedgerNode, accountId: string, signerKp: KeyPair): Promise<Agent> {
    const view = await node.account(accountId);
    if (view.signer.key !== signerKp.public.hex) throw new Error("signer key does not operate this account");
    return new Agent(node, null, new AgentSigner(signerKp, Policy.fromDict(view.policy), view.id), view);
  }

  get address(): string { return this.account.address; }

  async refresh(): Promise<AccountView> {
    this.account = await this.node.account(this.account.id);
    this.signer.policy = Policy.fromDict(this.account.policy);
    return this.account;
  }

  private async submit(op: string, params: Record<string, Json>, spend: bigint = 0n, payee = ""): Promise<Record<string, Json>> {
    await this.refresh();
    const { now } = await this.node.now();
    const body = { account: this.account.id, nonce: this.account.nonce, op, ...params };
    const snapshot = [...this.signer.window.entries] as [bigint, bigint][];
    const env = spend || payee ? this.signer.signPayment(payee, spend, now, body) : this.signer.signPlain(body);
    try {
      const { result } = await this.node.tx(env.toDict());
      return result;
    } catch (e) {
      this.signer.rollback(snapshot); // the ledger refused: the signer must not keep a spend that never happened
      throw e;
    }
  }

  transfer(to: string, asset: string, amount: bigint): Promise<Record<string, Json>> {
    return this.submit("transfer", { to, asset, amount }, amount, to);
  }

  async openChannel(payee: string, asset: string, deposit: bigint, timeoutSecs: bigint = 3600n, salt: bigint = 0n): Promise<string> {
    const r = await this.submit("open_channel", { payee, asset, deposit, timeout_secs: timeoutSecs, salt }, deposit, payee);
    return r.channel_id as string;
  }

  async joinPool(poolId: string, deposit: bigint): Promise<void> {
    const pool = await this.node.pool(poolId);
    await this.submit("join_pool", { pool_id: poolId, deposit }, deposit, pool.coordinator);
  }

  closeChannel(channelId: string): Promise<Record<string, Json>> {
    const latest = this.latest.get(channelId);
    return this.submit("close_channel", { channel_id: channelId, latest: latest ? (latest.toDict() as unknown as Json) : null });
  }

  finalizeClose(channelId: string): Promise<Record<string, Json>> {
    return this.submit("finalize_close", { channel_id: channelId });
  }

  beginExit(poolId: string): Promise<Record<string, Json>> {
    const latest = this.latest.get(poolId);
    return this.submit("begin_exit", { pool_id: poolId, latest: latest ? (latest.toDict() as unknown as Json) : null });
  }

  async finalizeExit(poolId: string): Promise<Record<string, Json>> {
    const r = await this.submit("finalize_exit", { pool_id: poolId });
    // the claim is gone: a later rejoin starts a fresh membership (new epoch, balance from 0)
    this.latest.delete(poolId);
    this.poolSeq.delete(poolId);
    this.signer.forget(poolId);
    return r;
  }

  /** Sign the next channel update adding `amount` for the payee. Off-chain; nothing is sent. */
  async payChannel(channelId: string, amount: bigint): Promise<Signed> {
    const ch = await this.node.channel(channelId);
    const deposit = fromNode(ch as unknown as Record<string, unknown>, "deposit", "channel");
    const seq = (this.channelSeq.get(channelId) ?? fromNode(ch as unknown as Record<string, unknown>, "seq", "channel")) + 1n;
    const prev = this.latest.has(channelId)
      ? (this.latest.get(channelId)!.body.balance as bigint)
      : fromNode(ch as unknown as Record<string, unknown>, "balance_to_payee", "channel");
    const balance = prev + amount;
    if (balance > deposit) throw new RangeError("channel deposit exhausted");
    const { now } = await this.node.now();
    const u = this.signer.signUpdate("channel", channelId, ch.payee, seq, balance, now);
    this.channelSeq.set(channelId, seq);
    this.latest.set(channelId, u);
    return u;
  }

  async payPool(poolId: string, amount: bigint): Promise<Signed> {
    const pool = await this.node.pool(poolId);
    const claim = pool.members[this.account.id];
    if (!claim || claim.exited) throw new Error("not a member of this pool");
    const c = claim as unknown as Record<string, unknown>;
    const deposit = fromNode(c, "deposit", "pool claim");
    const seq = (this.poolSeq.get(poolId) ?? fromNode(c, "seq", "pool claim")) + 1n;
    const prev = this.latest.has(poolId)
      ? (this.latest.get(poolId)!.body.balance as bigint)
      : fromNode(c, "paid", "pool claim");
    const balance = prev + amount;
    if (balance > deposit) throw new RangeError("pool deposit exhausted");
    const { now } = await this.node.now();
    const u = this.signer.signUpdate("pool", poolId, pool.coordinator, seq, balance, now, fromNode(c, "epoch", "pool claim"));
    this.poolSeq.set(poolId, seq);
    this.latest.set(poolId, u);
    return u;
  }
}
