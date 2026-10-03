/**
 * The client against a node it does not control.
 *
 * `AgentSigner` exists so that the enclave side does not take the node's word for the policy, so
 * what a hostile or merely broken node can make this client do is a security property and not
 * only a robustness one. The e2e suite covers the agreeable node; this one serves the responses a
 * live node will not, over an injected `fetchFn`.
 *
 * It is also the only place `Agent.attach` and `payPool` are reachable without a ledger, and
 * `payPool` is part of the hot path the bigint migration was for.
 */
import { describe, expect, it } from "vitest";
import { Agent, AgentSigner, LedgerNode, Policy, PolicyViolation } from "../src/agent.js";
import { KeyPair } from "../src/crypto.js";

const SIGNER = KeyPair.fromSeed("stub-signer");
const ACCOUNT = "a".repeat(64);
const POOL = "p".repeat(64);
const COORDINATOR = "0x" + "cd".repeat(20);

/** A node that answers the three GETs `attach` and `payPool` make, from canned JSON text. */
function stubNode(routes: Record<string, string>): LedgerNode {
  return new LedgerNode("http://node", async (url) => {
    const path = String(url).replace("http://node", "");
    const body = routes[path];
    if (body === undefined) return new Response(`no route ${path}`, { status: 404 });
    return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
  });
}

/** `policy` goes in as JSON text, so a test can serve a field no typed value could express. */
function routes(policy: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    "/ledger/now": '{"now":1000}',
    [`/ledger/accounts/${ACCOUNT}`]: `{
      "id": "${ACCOUNT}", "address": "account:${ACCOUNT}",
      "owner": {"scheme":"ed25519","key":"${KeyPair.fromSeed("stub-owner").public.hex}"},
      "signer": {"scheme":"ed25519","key":"${SIGNER.public.hex}"},
      "policy": ${policy},
      "nonce": 0, "parent": null, "spent_in_window": 0, "balances": {"USDC": 1000}
    }`,
    ...extra,
  };
}

const WIDE = `{
  "per_tx_max": 340282366920938463463374607431768211455,
  "per_window_max": 340282366920938463463374607431768211455,
  "window_secs": 3600, "allow_list": null, "deny_list": [], "expiry": null, "escalation": null
}`;

function poolRoute(deposit: string, paid: string, coordinator = COORDINATOR): Record<string, string> {
  return {
    [`/ledger/pools/${POOL}`]: `{
      "id": "${POOL}", "coordinator": "${coordinator}", "asset": "USDC", "timeout_secs": 60,
      "members": {"${ACCOUNT}": {"deposit": ${deposit}, "paid": ${paid}, "seq": 4, "exit_at": null, "exited": false, "epoch": 2}}
    }`,
  };
}

describe("Agent.attach", () => {
  it("attaches to an account whose co-signer the node stores as an address", async () => {
    // spec §2 permits it and the Python node stores and serves it, so this was an account the
    // reference considered valid and this client could not open at all: fromDict called
    // PublicKey.fromDict unconditionally and @noble threw "hex string expected, got undefined"
    const esc = "0x" + "EF".repeat(20);
    const node = stubNode(routes(WIDE.replace('"escalation": null', `"escalation": "${esc}"`)));
    const agent = await Agent.attach(node, ACCOUNT, SIGNER);
    expect(agent.signer.policy.escalation).toBe("0x" + "ef".repeat(20)); // §2.1, canonical
    expect(agent.account.id).toBe(ACCOUNT);
  });

  it("refuses a window_secs of 0 rather than enforcing no window at all", async () => {
    // the fail-open: with window_secs 0 the signer's cutoff is `now - 0n` and the filter is
    // `t > cutoff`, so a spend is pruned the instant it is recorded and per_window_max is gone.
    // Attaching must fail, not succeed with an unenforceable policy.
    const node = stubNode(routes(WIDE.replace('"window_secs": 3600', '"window_secs": 0')));
    await expect(Agent.attach(node, ACCOUNT, SIGNER)).rejects.toThrow("window_secs must be in [1, 2592000]");
  });

  it("refuses an amount the node serves above 2^128", async () => {
    const node = stubNode(routes(WIDE.replace(
      '"per_window_max": 340282366920938463463374607431768211455',
      '"per_window_max": 340282366920938463463374607431768211456',
    )));
    await expect(Agent.attach(node, ACCOUNT, SIGNER)).rejects.toThrow(
      "per_window_max must be an integer in [0, 2^128)",
    );
  });

  it("enforces a deny list the node spells differently from the channel payee", async () => {
    // the §2.1 failure in its live shape: the policy denies the provider in lowercase, the node
    // stores the pool's coordinator in mixed case, and nothing matched, so the signer kept
    // signing updates in favour of a payee the owner had barred
    const node = stubNode({
      ...routes(WIDE.replace('"deny_list": []', `"deny_list": ["${COORDINATOR}"]`)),
      ...poolRoute("1000", "0", COORDINATOR.toUpperCase().replace("0X", "0x")),
    });
    const agent = await Agent.attach(node, ACCOUNT, SIGNER);
    await expect(agent.payPool(POOL, 1n)).rejects.toThrow(`payee ${COORDINATOR} is denied`);
  });
});

describe("payPool above 2^53", () => {
  const PAID = 123456789012345678901n;

  it("adds to a balance no double represents, and signs the digits", async () => {
    const node = stubNode({ ...routes(WIDE), ...poolRoute("10".padEnd(31, "0"), String(PAID)) });
    const agent = await Agent.attach(node, ACCOUNT, SIGNER);
    const u = await agent.payPool(POOL, 7n);
    expect(u.body.balance).toBe(PAID + 7n); // PAID + 7 is PAID as a double
    expect(u.body.seq).toBe(5n);
    expect(u.body.epoch).toBe(2n);
    expect(u.valid()).toBe(true);
    // the digits, not 1.2345678901234568e+20: PAID + 7 is PAID as a double
    expect(String(u.body.balance)).toBe("123456789012345678908");
  });

  it("refuses an amount one unit past the deposit", async () => {
    const deposit = PAID + 10n;
    const node = stubNode({ ...routes(WIDE), ...poolRoute(String(deposit), String(PAID)) });
    const agent = await Agent.attach(node, ACCOUNT, SIGNER);
    await expect(agent.payPool(POOL, 11n)).rejects.toThrow("pool deposit exhausted");
    const u = await agent.payPool(POOL, 10n); // exactly the deposit is allowed
    expect(u.body.balance).toBe(deposit);
  });
});

describe("payChannel above 2^53", () => {
  // the live node cannot be used for this: its devnet faucet mints at most 1,000,000, so a
  // deposit at these magnitudes is unfundable there. The signature over the update is the same
  // computation either way, and the cross-language vector in precision.test.ts pins it to the
  // bytes foliant/crypto.py produces.
  const SETTLED = 123456789012345678901n;

  function channelRoute(deposit: string, balance: string): Record<string, string> {
    return {
      [`/ledger/channels/${POOL}`]: `{
        "id": "${POOL}", "payer_account": "${ACCOUNT}", "payee": "${COORDINATOR}", "asset": "USDC",
        "deposit": ${deposit}, "balance_to_payee": ${balance}, "seq": 4, "timeout_secs": 60,
        "closing_at": null, "closed": false
      }`,
    };
  }

  it("adds to a settled balance no double represents", async () => {
    const node = stubNode({ ...routes(WIDE), ...channelRoute("10".padEnd(31, "0"), String(SETTLED)) });
    const agent = await Agent.attach(node, ACCOUNT, SIGNER);
    const u = await agent.payChannel(POOL, 7n);
    expect(String(u.body.balance)).toBe("123456789012345678908");
    expect(u.body.seq).toBe(5n);
    expect(u.valid()).toBe(true);
    // the second update builds on the first, not on the node's settled figure
    const u2 = await agent.payChannel(POOL, 7n);
    expect(String(u2.body.balance)).toBe("123456789012345678915");
  });

  it("refuses an amount one unit past the deposit", async () => {
    const node = stubNode({ ...routes(WIDE), ...channelRoute(String(SETTLED + 10n), String(SETTLED)) });
    const agent = await Agent.attach(node, ACCOUNT, SIGNER);
    await expect(agent.payChannel(POOL, 11n)).rejects.toThrow("channel deposit exhausted");
    expect((await agent.payChannel(POOL, 10n)).body.balance).toBe(SETTLED + 10n);
  });
});

describe("AgentSigner window", () => {
  it("meters per_window_max over the window the policy names", () => {
    const signer = new AgentSigner(SIGNER, new Policy(100n, 150n, 60n), ACCOUNT);
    signer.signPayment(COORDINATOR, 100n, 1000n, { a: 1n });
    expect(() => signer.signPayment(COORDINATOR, 100n, 1000n, { a: 1n })).toThrow(PolicyViolation);
    // and the first spend ages out of a 60-second window, where window_secs 0 would have dropped
    // it immediately -- which is why the lower bound is enforced
    expect(() => signer.signPayment(COORDINATOR, 100n, 1061n, { a: 1n })).not.toThrow();
  });
});

describe("a view the node sent is checked, not asserted", () => {
  // `LedgerNode.call` ends in `parseJsonBig(...) as T`, which is an assertion about someone else's
  // document rather than a check of it. The deposit guard is the only bound an off-chain update
  // has (spec §7.1: the deposit is the spend, already checked against the policy when the channel
  // was opened), and every one of `bigint > undefined`, `bigint > "100"` and `bigint > {}` is
  // false -- so each of these used to get an update signed for any amount at all.
  const BAD: [string, string][] = [
    ["missing", ""],
    ["a string", '"deposit": "1000000000000000000000",'],
    ["an object", '"deposit": {},'],
    ["null", '"deposit": null,'],
  ];

  it.each(BAD)("refuses to sign a pool update when deposit is %s", async (_name, field) => {
    const pool = `{
      "id": "${POOL}", "coordinator": "${COORDINATOR}", "asset": "USDC", "timeout_secs": 60,
      "members": {"${ACCOUNT}": {${field} "paid": 0, "seq": 4, "exit_at": null, "exited": false, "epoch": 2}}
    }`;
    const node = stubNode(routes(WIDE, { [`/ledger/pools/${POOL}`]: pool }));
    const agent = await Agent.attach(node, ACCOUNT, SIGNER);
    await expect(agent.payPool(POOL, 10n ** 30n)).rejects.toThrow(
      /pool claim: deposit is (missing|not an integer)/,
    );
  });

  it("still signs when the node answers properly", async () => {
    const node = stubNode(routes(WIDE, poolRoute("1000000000000000000000", "0")));
    const agent = await Agent.attach(node, ACCOUNT, SIGNER);
    const u = await agent.payPool(POOL, 10n ** 18n);
    expect(u.body.balance).toBe(10n ** 18n);
    expect(u.valid()).toBe(true);
  });
});
