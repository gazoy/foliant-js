/**
 * x402 on the wire: answer a 402 with a Foliant channel or pool update.
 * Headers and body shapes match foliant/x402.py (X-PAYMENT, X-PAYMENT-RESPONSE, `accepts`).
 */
import { Agent } from "./agent.js";
import { canonical, Json, SignedDict } from "./crypto.js";

export const HDR_PAYMENT = "X-PAYMENT";
export const HDR_RECEIPT = "X-PAYMENT-RESPONSE";

export interface PaymentTerms {
  scheme: "foliant-channel" | "foliant-pool" | string;
  network: string;
  payTo: string;
  asset: string;
  maxAmountRequired: string;
  unit?: string;
  offerId?: string;
  requiredCodeHash?: string | null;
  poolId?: string;
}

export interface PaymentRequired {
  x402Version: number;
  accepts: PaymentTerms[];
  error?: string;
}

export interface Receipt {
  body: { updateId: string; requestHash: string; responseHash: string; offerId: string };
  signer: { scheme: string; key: string };
  signature: string;
}

function b64(obj: Json): string {
  // canonical(), not JSON.stringify(): the update body carries bigint amounts and seq numbers, and
  // JSON.stringify throws on a bigint outright. The Python side decodes with json.loads, to which
  // key order is irrelevant, so canonical's sorted output is read the same way.
  const bytes = new TextEncoder().encode(canonical(obj));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function unb64<T>(s: string): T {
  const bin = atob(s);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

export interface PayingClientOptions {
  defaultDeposit?: bigint;
  preferPool?: boolean;
  timeoutSecs?: bigint;
  fetchFn?: typeof fetch;
}

/** Retries a 402 with a payment, opening a channel or joining a pool on demand. */
export class PayingClient {
  readonly receipts: Receipt[] = [];
  private readonly defaultDeposit: bigint;
  private readonly preferPool: boolean;
  private readonly timeoutSecs: bigint;
  private readonly fetchFn: typeof fetch;

  constructor(public readonly agent: Agent, opts: PayingClientOptions = {}) {
    this.defaultDeposit = opts.defaultDeposit ?? 100n;
    this.preferPool = opts.preferPool ?? true;
    this.timeoutSecs = opts.timeoutSecs ?? 3600n;
    this.fetchFn = opts.fetchFn ?? globalThis.fetch.bind(globalThis);
  }

  choose(accepts: PaymentTerms[]): PaymentTerms {
    if (this.preferPool) {
      const p = accepts.find((a) => a.scheme === "foliant-pool");
      if (p) return p;
    }
    const c = accepts.find((a) => a.scheme === "foliant-channel");
    if (!c) throw new Error("no Foliant scheme in the 402 terms");
    return c;
  }

  private async paymentFor(term: PaymentTerms): Promise<string> {
    const agent = this.agent;
    // the x402 wire carries amounts as decimal strings, which BigInt reads exactly at any size;
    // Number() was rounding them before the policy ever saw the figure
    const price = BigInt(term.maxAmountRequired);
    if (term.scheme === "foliant-pool") {
      const pid = term.poolId!;
      const pool = await agent.node.pool(pid);
      const claim = pool.members[agent.account.id];
      if (!claim || claim.exited) await agent.joinPool(pid, this.defaultDeposit);
      const update = await agent.payPool(pid, price);
      return b64({ scheme: "foliant-pool", id: pid, update: update.toDict() as unknown as Json });
    }
    // channel: reuse an open one to this payee with room, else open another
    let cid: string | null = null;
    for (const [id, u] of agent.latest) {
      if (u.body.kind !== "channel") continue;
      const ch = await agent.node.channel(id);
      if (ch.payee === term.payTo && ch.asset === term.asset && !ch.closed && ch.closing_at === null
          && (u.body.balance as bigint) + price <= ch.deposit) {
        cid = id;
        break;
      }
    }
    if (cid === null) {
      cid = await agent.openChannel(term.payTo, term.asset, this.defaultDeposit, this.timeoutSecs, BigInt(Date.now()));
    }
    const update = await agent.payChannel(cid, price);
    return b64({ scheme: "foliant-channel", id: cid, update: update.toDict() as unknown as Json });
  }

  async fetch(url: string, init: RequestInit = {}): Promise<Response> {
    let r = await this.fetchFn(url, init);
    if (r.status !== 402) return r;
    const terms = (await r.json()) as PaymentRequired;
    const term = this.choose(terms.accepts);
    const headers = new Headers(init.headers ?? {});
    headers.set(HDR_PAYMENT, await this.paymentFor(term));
    r = await this.fetchFn(url, { ...init, headers });
    const rc = r.headers.get(HDR_RECEIPT);
    if (rc) this.receipts.push(unb64<Receipt>(rc));
    return r;
  }
}

export type { SignedDict };
