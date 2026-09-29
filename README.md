# foliant-client

TypeScript client for [Foliant](https://foliant.network): budgeted agent accounts, payment channels and pools, and paying x402 endpoints against a Foliant ledger node. The agent side of the [reference implementation](https://github.com/gazoy/concord), byte-compatible with it: keys, addresses, canonical hashing and signatures are tested against vectors produced by the Python code.

```bash
npm install foliant-client
```

```ts
import { Agent, KeyPair, LedgerNode, PayingClient, Policy } from "foliant-client";

const node = new LedgerNode("http://127.0.0.1:8402");           // python demo/serve.py in the reference repo
const agent = await Agent.register(node, KeyPair.generate(), KeyPair.generate(), new Policy(500, 200, 3600));
await node.faucet(agent.address, "USDC", 10_000);                // devnet only

const client = new PayingClient(agent, { defaultDeposit: 100 });
const r = await client.fetch("http://127.0.0.1:8402/infer", { method: "POST", body: "hello" });
// 402 answered with a signed pool update; r.status === 200; client.receipts[0] is the provider-signed receipt
```

The signer refuses to sign outside the account's policy (`PolicyViolation`); the ledger refuses again, and against every ancestor's policy in a crew, when a deposit is applied. Off-chain updates are bounded by the deposit they draw on, so a session of calls costs one deposit and one settlement.

`Agent.attach(node, accountId, signerKey)` operates an account that already exists, for example one an orchestrator delegated.

## Tests

`npm test` runs the cross-language vectors and an end-to-end test that starts the Python node (`python demo/serve.py`) from a checkout of the reference repo at `/home/claude/concord`; set `FOLIANT_REF` to point elsewhere.

Apache-2.0. Copyright 2026 Machine Quotient Ltd.
