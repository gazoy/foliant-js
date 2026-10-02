/**
 * Foliant client against a ledger node (foliant/node.py) — the agent side of
 * foliant/agent.py and foliant/x402.py, in TypeScript.
 *
 * The signer enforces the account's own policy before signing anything, as the
 * Python AgentSigner does; the ledger enforces it again, and every ancestor's,
 * when a deposit is applied. Off-chain updates are bounded by the deposit they
 * draw on.
 */
import { hashObj, Json, KeyPair, PublicKey, sign, Signed, SignedDict } from "./crypto.js";

export interface PolicyDict {
  per_tx_max: number;
  per_window_max: number;
  window_secs: number;
  allow_list: string[] | null;
  deny_list: string[];
  expiry: number | null;
  escalation: { scheme: string; key: string } | null;
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

/**
 * TypeScript rejects an excess property on an object *literal* typed as PolicyDict, but not on a
 * variable and not on anything that came back from JSON.parse -- which is every policy this client
 * actually sees. So the check has to exist at runtime.
 */
function rejectUnknown(d: unknown, allowed: ReadonlySet<string>): void {
  if (typeof d !== "object" || d === null || Array.isArray(d)) {
    const got = d === null ? "null" : Array.isArray(d) ? "array" : typeof d;
    throw new PolicyViolation(`policy must be an object, not ${got}`);
  }
  // quote then sort, so the list reads the same as the Python reference's sorted repr()
  const unknown = Object.keys(d).filter((k) => !allowed.has(k)).map((k) => `'${k}'`).sort();
  if (unknown.length) throw new PolicyViolation(`unknown policy field(s): ${unknown.join(", ")}`);
}

export class Policy {
  constructor(
    public perTxMax: number,
    public perWindowMax: number,
    public windowSecs: number,
    public allowList: Set<string> | null = null,
    public denyList: Set<string> = new Set(),
    public expiry: number | null = null,
    public escalation: PublicKey | null = null,
  ) {}

  toDict(): PolicyDict {
    return {
      per_tx_max: this.perTxMax,
      per_window_max: this.perWindowMax,
      window_secs: this.windowSecs,
      allow_list: this.allowList ? [...this.allowList].sort() : null,
      deny_list: [...this.denyList].sort(),
      expiry: this.expiry,
      escalation: this.escalation ? this.escalation.toDict() : null,
    };
  }

  static fromDict(d: PolicyDict): Policy {
    rejectUnknown(d, DICT_FIELDS);
    return new Policy(
      d.per_tx_max, d.per_window_max, d.window_secs,
      d.allow_list ? new Set(d.allow_list) : null, new Set(d.deny_list ?? []), d.expiry ?? null,
      d.escalation ? PublicKey.fromDict(d.escalation) : null,
    );
  }

  get id(): string {
    return hashObj(this.toDict() as unknown as Json);
  }

  /** Same checks, same order, same messages as Policy.check in Python. */
  check(amount: number, payee: string, now: number, spentInWindow: number, escalated = false): void {
    if (amount < 0) throw new PolicyViolation("negative amount");
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
  entries: [number, number][] = [];
  spent(now: number, windowSecs: number): number {
    const cutoff = now - windowSecs;
    this.entries = this.entries.filter(([t]) => t > cutoff);
    return this.entries.reduce((a, [, v]) => a + v, 0);
  }
  record(now: number, amount: number): void {
    this.entries.push([now, amount]);
  }
}

/** The enclave side: holds the signer key and refuses to sign outside policy. */
export class AgentSigner {
  readonly window = new SpendWindow();
  private lastBalance = new Map<string, number>();

  constructor(public readonly keypair: KeyPair, public policy: Policy, public readonly accountId: string) {}

  signPayment(payee: string, amount: number, now: number, body: { [k: string]: Json }, escalated = false): Signed {
    const spent = this.window.spent(now, this.policy.windowSecs);
    this.policy.check(amount, payee, now, spent, escalated);
    this.window.record(now, amount);
    return sign(this.keypair, body);
  }

  signUpdate(kind: "channel" | "pool", objId: string, payee: string, seq: number, balance: number, now: number, epoch?: number): Signed {
    const last = this.lastBalance.get(objId) ?? 0;
    if (balance < last) throw new PolicyViolation("balance must not decrease");
    const spent = this.window.spent(now, this.policy.windowSecs);
    this.policy.check(0, payee, now, spent);
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

  rollback(snapshot: [number, number][]): void {
    this.window.entries = snapshot;
  }
}

export interface AccountView {
  id: string;
  address: string;
  owner: { scheme: string; key: string };
  signer: { scheme: string; key: string };
  policy: PolicyDict;
  nonce: number;
  parent: string | null;
  spent_in_window: number;
  balances: Record<string, number>;
}

export interface ChannelView {
  id: string; payer_account: string; payee: string; asset: string; deposit: number;
  balance_to_payee: number; seq: number; timeout_secs: number; closing_at: number | null; closed: boolean;
}

export interface PoolView {
  id: string; coordinator: string; asset: string; timeout_secs: number;
  members: Record<string, { deposit: number; paid: number; seq: number; exit_at: number | null; exited: boolean; epoch: number }>;
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
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!r.ok) {
      let detail = await r.text();
      try {
        detail = JSON.parse(detail).detail ?? detail;
      } catch { /* plain text */ }
      if (r.status === 400 && String(detail).startsWith("PolicyViolation")) throw new PolicyViolation(String(detail).replace(/^PolicyViolation: /, ""));
      throw new LedgerError(String(detail), r.status);
    }
    return (await r.json()) as T;
  }

  now(): Promise<{ now: number }> { return this.call("GET", "/ledger/now"); }
  account(id: string): Promise<AccountView> { return this.call("GET", `/ledger/accounts/${id}`); }
  channel(id: string): Promise<ChannelView> { return this.call("GET", `/ledger/channels/${id}`); }
  pool(id: string): Promise<PoolView> { return this.call("GET", `/ledger/pools/${id}`); }
  balance(address: string, asset: string): Promise<{ balance: number }> { return this.call("GET", `/ledger/balances/${address}/${asset}`); }
  faucet(address: string, asset: string, amount: number): Promise<{ balance: number }> {
    return this.call("POST", "/ledger/faucet", { address, asset, amount });
  }
  register(ownerSigned: SignedDict, signer: { scheme: string; key: string }, policy: PolicyDict, salt = 0): Promise<AccountView> {
    return this.call("POST", "/ledger/accounts", { owner_signed: ownerSigned, signer, policy, salt });
  }
  tx(envelope: SignedDict, escalation?: SignedDict): Promise<{ result: Record<string, Json> }> {
    return this.call("POST", "/ledger/tx", { envelope, escalation: escalation ?? null });
  }
}

/** An agent: one account on the node, operated by a signer under a policy. */
export class Agent {
  readonly latest = new Map<string, Signed>();
  private channelSeq = new Map<string, number>();
  private poolSeq = new Map<string, number>();

  private constructor(
    public readonly node: LedgerNode,
    public readonly owner: KeyPair | null,
    public readonly signer: AgentSigner,
    public account: AccountView,
  ) {}

  /** Register a new account: the owner signs the registration, the signer operates it. */
  static async register(node: LedgerNode, owner: KeyPair, signerKp: KeyPair, policy: Policy, salt = 0): Promise<Agent> {
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

  private async submit(op: string, params: Record<string, Json>, spend = 0, payee = ""): Promise<Record<string, Json>> {
    await this.refresh();
    const { now } = await this.node.now();
    const body = { account: this.account.id, nonce: this.account.nonce, op, ...params };
    const snapshot = [...this.signer.window.entries] as [number, number][];
    const env = spend || payee ? this.signer.signPayment(payee, spend, now, body) : this.signer.signPlain(body);
    try {
      const { result } = await this.node.tx(env.toDict());
      return result;
    } catch (e) {
      this.signer.rollback(snapshot); // the ledger refused: the signer must not keep a spend that never happened
      throw e;
    }
  }

  transfer(to: string, asset: string, amount: number): Promise<Record<string, Json>> {
    return this.submit("transfer", { to, asset, amount }, amount, to);
  }

  async openChannel(payee: string, asset: string, deposit: number, timeoutSecs = 3600, salt = 0): Promise<string> {
    const r = await this.submit("open_channel", { payee, asset, deposit, timeout_secs: timeoutSecs, salt }, deposit, payee);
    return r.channel_id as string;
  }

  async joinPool(poolId: string, deposit: number): Promise<void> {
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
  async payChannel(channelId: string, amount: number): Promise<Signed> {
    const ch = await this.node.channel(channelId);
    const seq = (this.channelSeq.get(channelId) ?? ch.seq) + 1;
    const prev = this.latest.has(channelId) ? (this.latest.get(channelId)!.body.balance as number) : ch.balance_to_payee;
    const balance = prev + amount;
    if (balance > ch.deposit) throw new RangeError("channel deposit exhausted");
    const { now } = await this.node.now();
    const u = this.signer.signUpdate("channel", channelId, ch.payee, seq, balance, now);
    this.channelSeq.set(channelId, seq);
    this.latest.set(channelId, u);
    return u;
  }

  async payPool(poolId: string, amount: number): Promise<Signed> {
    const pool = await this.node.pool(poolId);
    const claim = pool.members[this.account.id];
    if (!claim || claim.exited) throw new Error("not a member of this pool");
    const seq = (this.poolSeq.get(poolId) ?? claim.seq) + 1;
    const prev = this.latest.has(poolId) ? (this.latest.get(poolId)!.body.balance as number) : claim.paid;
    const balance = prev + amount;
    if (balance > claim.deposit) throw new RangeError("pool deposit exhausted");
    const { now } = await this.node.now();
    const u = this.signer.signUpdate("pool", poolId, pool.coordinator, seq, balance, now, claim.epoch);
    this.poolSeq.set(poolId, seq);
    this.latest.set(poolId, u);
    return u;
  }
}
