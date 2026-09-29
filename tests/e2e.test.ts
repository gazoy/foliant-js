/** End to end: the Python ledger node + metered API, driven by the TypeScript client. */
import { spawn, ChildProcess } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Agent, KeyPair, LedgerNode, PayingClient, Policy, PolicyViolation } from "../src/index.js";

const PORT = 8412;
const BASE = `http://127.0.0.1:${PORT}`;
const ASSET = "USDC";
let server: ChildProcess;

async function waitUp(): Promise<void> {
  for (let i = 0; i < 100; i++) {
    try {
      const r = await fetch(`${BASE}/ledger/now`);
      if (r.ok) return;
    } catch { /* not yet */ }
    await new Promise((res) => setTimeout(res, 100));
  }
  throw new Error("server did not start");
}

beforeAll(async () => {
  server = spawn("python3", ["demo/serve.py", String(PORT)], { cwd: process.env.FOLIANT_REF ?? "/home/claude/concord", stdio: "ignore" });
  await waitUp();
}, 30_000);

afterAll(() => {
  server.kill();
});

describe("TypeScript agent against the Python node", () => {
  it("registers, funds, pays 20 calls through a pool, and the provider settles once", async () => {
    const node = new LedgerNode(BASE);
    const policy = new Policy(500, 200, 3600);
    const agent = await Agent.register(node, KeyPair.fromSeed("ts-owner"), KeyPair.fromSeed("ts-signer"), policy);
    await node.faucet(agent.address, ASSET, 10_000);
    const client = new PayingClient(agent, { defaultDeposit: 100, preferPool: true });
    for (let i = 0; i < 20; i++) {
      const r = await client.fetch(`${BASE}/infer`, { method: "POST", body: `prompt ${i}` });
      expect(r.status).toBe(200);
      expect(await r.text()).toContain(`prompt ${i}`);
    }
    expect(client.receipts.length).toBe(20);
    expect(client.receipts[0].body.offerId).toBeTruthy();
    const acct = await agent.refresh();
    expect(acct.spent_in_window).toBe(100); // one pool deposit is the committed value; 20 updates cost nothing more
    const settle = await (await fetch(`${BASE}/settle`, { method: "POST" })).json();
    expect(settle.settled).toBe(60);
  });

  it("is refused by its own policy, and the signer's window matches the ledger's", async () => {
    const node = new LedgerNode(BASE);
    const agent = await Agent.register(node, KeyPair.fromSeed("ts-owner-2"), KeyPair.fromSeed("ts-signer-2"), new Policy(500, 200, 3600));
    await node.faucet(agent.address, ASSET, 10_000);
    const client = new PayingClient(agent, { defaultDeposit: 100, preferPool: false });
    let refused: unknown = null;
    let ok = 0;
    for (let i = 0; i < 100 && !refused; i++) {
      try {
        await client.fetch(`${BASE}/infer`, { method: "POST", body: "x" });
        ok++;
      } catch (e) {
        refused = e;
      }
    }
    expect(refused).toBeInstanceOf(PolicyViolation);
    expect(String((refused as Error).message)).toContain("per_window_max 200");
    expect(ok).toBe(66); // two 100-unit channels at 3 per call, as in the Python demo's scenario C
    const acct = await agent.refresh();
    expect(acct.spent_in_window).toBe(200);
    expect(agent.signer.window.spent((await node.now()).now, 3600)).toBe(200);
  });

  it("recovers its deposit alone when it closes a channel", async () => {
    const node = new LedgerNode(BASE);
    const provider = KeyPair.fromSeed("provider").address;
    const agent = await Agent.register(node, KeyPair.fromSeed("ts-owner-3"), KeyPair.fromSeed("ts-signer-3"), new Policy(500, 500, 3600));
    await node.faucet(agent.address, ASSET, 1_000);
    const cid = await agent.openChannel(provider, ASSET, 100, 1);
    await agent.payChannel(cid, 30);
    await agent.closeChannel(cid);
    const before = (await node.balance(agent.address, ASSET)).balance;
    await new Promise((res) => setTimeout(res, 1_500)); // the served devnet's clock follows wall time
    await agent.finalizeClose(cid);
    expect((await node.balance(agent.address, ASSET)).balance).toBe(before + 70);
    const ch = await node.channel(cid);
    expect(ch.closed).toBe(true);
    expect(ch.balance_to_payee).toBe(30);
  });
});
