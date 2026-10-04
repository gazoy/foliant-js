/** End to end: the Python ledger node + metered API, driven by the TypeScript client. */
import { spawn, ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Agent, KeyPair, LedgerNode, PayingClient, Policy, PolicyViolation } from "../src/index.js";

const PORT = 8412;
const BASE = `http://127.0.0.1:${PORT}`;
const ASSET = "USDC";
let server: ChildProcess;
// The node's own output, kept so a failure to start can say why instead of timing out mutely.
let serverOutput = "";

async function waitUp(): Promise<void> {
  for (let i = 0; i < 100; i++) {
    try {
      const r = await fetch(`${BASE}/ledger/now`);
      if (r.ok) return;
    } catch { /* not yet */ }
    await new Promise((res) => setTimeout(res, 100));
  }
  throw new Error(
    "The ledger node did not answer on " + BASE + " within 10s." +
      (serverOutput.trim() ? "\nIts output was:\n" + serverOutput.trim() : "\nIt produced no output.") +
      "\nIf that names a missing module, install the reference's dependencies into the python3 on PATH: " +
      "python3 -m pip install -r requirements.txt, from the reference checkout.",
  );
}

beforeAll(async () => {
  const ref = process.env.FOLIANT_REF ?? resolve(dirname(fileURLToPath(import.meta.url)), "../../concord");
  if (!existsSync(resolve(ref, "demo/serve.py"))) {
    throw new Error(
      `The Foliant reference implementation is not at ${ref}. This suite drives its demo/serve.py ` +
        `ledger node. Clone https://github.com/gazoy/concord beside this repository, or set FOLIANT_REF.`,
    );
  }
  server = spawn("python3", ["demo/serve.py", String(PORT)], { cwd: ref, stdio: ["ignore", "pipe", "pipe"] });
  server.stdout?.on("data", (d) => { serverOutput += d.toString(); });
  server.stderr?.on("data", (d) => { serverOutput += d.toString(); });
  server.on("exit", (code) => { if (code !== 0 && code !== null) serverOutput += `\n(the node exited with code ${code})`; });
  server.on("error", (e) => {
    throw new Error(`Could not start the ledger node from ${ref}: ${e.message}. Python 3.11 or newer must be on PATH.`);
  });
  await waitUp();
}, 30_000);

afterAll(() => {
  server.kill();
});

describe("TypeScript agent against the Python node", () => {
  it("registers, funds, pays 20 calls through a pool, and the provider settles once", async () => {
    const node = new LedgerNode(BASE);
    const policy = new Policy(500n, 200n, 3600n);
    const agent = await Agent.register(node, KeyPair.fromSeed("ts-owner"), KeyPair.fromSeed("ts-signer"), policy);
    await node.faucet(agent.address, ASSET, 10_000n);
    const client = new PayingClient(agent, { defaultDeposit: 100n, preferPool: true });
    for (let i = 0; i < 20; i++) {
      const r = await client.fetch(`${BASE}/infer`, { method: "POST", body: `prompt ${i}` });
      expect(r.status).toBe(200);
      expect(await r.text()).toContain(`prompt ${i}`);
    }
    expect(client.receipts.length).toBe(20);
    expect(client.receipts[0].body.offerId).toBeTruthy();
    const acct = await agent.refresh();
    expect(acct.spent_in_window).toBe(100n); // one pool deposit is the committed value; 20 updates cost nothing more
    // plain fetch().json(), not the client's bigint-preserving parse, so this one is a number
    const settle = await (await fetch(`${BASE}/settle`, { method: "POST" })).json();
    expect(settle.settled).toBe(60);
  });

  it("is refused by its own policy, and the signer's window matches the ledger's", async () => {
    const node = new LedgerNode(BASE);
    const agent = await Agent.register(node, KeyPair.fromSeed("ts-owner-2"), KeyPair.fromSeed("ts-signer-2"), new Policy(500n, 200n, 3600n));
    await node.faucet(agent.address, ASSET, 10_000n);
    const client = new PayingClient(agent, { defaultDeposit: 100n, preferPool: false });
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
    expect(acct.spent_in_window).toBe(200n);
    expect(agent.signer.window.spent((await node.now()).now, 3600n)).toBe(200n);
  });

  it("recovers its deposit alone when it closes a channel", async () => {
    const node = new LedgerNode(BASE);
    const provider = KeyPair.fromSeed("provider").address;
    const agent = await Agent.register(node, KeyPair.fromSeed("ts-owner-3"), KeyPair.fromSeed("ts-signer-3"), new Policy(500n, 500n, 3600n));
    await node.faucet(agent.address, ASSET, 1_000n);
    const cid = await agent.openChannel(provider, ASSET, 100n, 1n);
    await agent.payChannel(cid, 30n);
    await agent.closeChannel(cid);
    const before = (await node.balance(agent.address, ASSET)).balance;
    await new Promise((res) => setTimeout(res, 1_500)); // the served devnet's clock follows wall time
    await agent.finalizeClose(cid);
    expect((await node.balance(agent.address, ASSET)).balance).toBe(before + 70n);
    const ch = await node.channel(cid);
    expect(ch.closed).toBe(true);
    expect(ch.balance_to_payee).toBe(30n);
  });

  // No live test above 2^53: the served devnet's faucet is capped at 1,000,000 a call, so the node
  // cannot be funded to that scale. The client's own path at those magnitudes is in
  // precision.test.ts against a stubbed node, and agreement with foliant/crypto.py on the bytes
  // and the signature is the `big_integers` vectors, which the Python reference generated.

  it("registers a policy whose addresses are in mixed case", async () => {
    // The node canonicalises the lists it is given (§2.1, Policy.__post_init__) and hashes the
    // result, so a client that did not failed registration with "registration body does not match
    // parameters": `Agent.register` has the owner sign the id this client computed.
    const node = new LedgerNode(BASE);
    const allow = "0x" + "AB".repeat(20);
    const deny = "0x" + "CD".repeat(20);
    const policy = new Policy(500n, 2000n, 3600n, new Set([allow]), new Set([deny]));
    const agent = await Agent.register(
      node, KeyPair.fromSeed("ts-owner-case"), KeyPair.fromSeed("ts-signer-case"), policy,
    );
    // the node's own view of the policy hashes to the same id, which is what "same policy" means
    expect(Policy.fromDict(agent.account.policy).id).toBe(policy.id);
    expect([...Policy.fromDict(agent.account.policy).denyList]).toEqual([deny.toLowerCase()]);
    // and the signer evaluates a payee given in either case against it (vectors check-030/031)
    expect(() => agent.signer.policy.check(1n, allow, 1000n, 0n)).not.toThrow();
    expect(() => agent.signer.policy.check(1n, allow.toLowerCase(), 1000n, 0n)).not.toThrow();
    expect(() => agent.signer.policy.check(1n, deny.toLowerCase(), 1000n, 0n)).toThrow(/is denied/);
    expect(() => agent.signer.policy.check(1n, deny, 1000n, 0n)).toThrow(/is denied/);
  });

  it("attaches to an account whose co-signer is an address, which §2 permits", async () => {
    // The node accepts and stores an address-form escalation; `Policy.fromDict` called
    // PublicKey.fromDict on it unconditionally, so this threw a raw TypeError out of @noble
    // against a policy the node considered perfectly valid.
    const node = new LedgerNode(BASE);
    const signerKp = KeyPair.fromSeed("ts-signer-esc");
    const policy = new Policy(500n, 2000n, 3600n, null, new Set(), null, "0x" + "EE".repeat(20));
    const agent = await Agent.register(node, KeyPair.fromSeed("ts-owner-esc"), signerKp, policy);
    const again = await Agent.attach(node, agent.account.id, signerKp);
    expect(again.signer.policy.escalation).toBe("0x" + "ee".repeat(20));
    expect(again.signer.policy.id).toBe(policy.id);
  });
});
