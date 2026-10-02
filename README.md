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

## Limits

**Amounts are JavaScript `number`s, so this client is correct for assets with up to 6 decimals and
not for 18.** The Python reference and the contracts carry amounts as arbitrary-precision integers
and `uint128`; a `number` holds integers exactly only below 2^53 (9,007,199,254,740,992). Two
things follow, and neither announces itself:

- **Silent rounding above 2^53.** `JSON.parse` of a policy the node sent as
  `1234567890123456789` yields `1234567890123456768`. At 18 decimals 2^53 is about 0.009 of a
  token, so almost any realistic 18-decimal amount is already wrong by the time you see the object.
- **Divergent canonical bytes at 1e21 and above.** `canonical()` renders such a number the way
  JavaScript does, `2e+21`, where Python writes the digits. The same policy therefore hashes to two
  different `id`s in the two implementations, so `Agent.attach` disagrees with the ledger about
  which policy it is operating under; and because `AgentSigner.signUpdate` puts `balance` straight
  into the signed body, a channel or pool update at that scale produces a signature the Python node
  cannot verify. `canonical()`'s integer check catches fractions, but neither of these.

For a 6-decimal asset such as USDC the exact range runs to roughly 9 billion tokens, which is why
the cross-language vectors and the end-to-end test pass: they use USDC-scale amounts. Nothing in
the protocol caps amounts that low — the wire grammar is an unbounded unsigned integer and the
contracts accept up to `type(uint128).max` — so the ceiling is this client's, not the protocol's.

Fixing it means carrying amounts as `bigint` through `Policy`, `SpendWindow`, `signUpdate` and the
node response parse, the last of which needs the JSON handled before `JSON.parse` has already lost
the digits. That is a breaking API change and is tracked as separate work for 0.2.0, not a patch.

## Tests

`npm test` runs the cross-language vectors and an end-to-end test that starts the Python node (`python demo/serve.py`) from a checkout of the reference repo at `/home/claude/concord`; set `FOLIANT_REF` to point elsewhere.

Apache-2.0. Copyright 2026 Machine Quotient Ltd.
