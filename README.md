# One paid receipt from x402toll.com, checked against GVP 0.2

A directed reproduction by a reader of the spec. Not an independent audit, not a certification, and not an endorsement of the service or of any paid route.

## What this is

On 2026-11-17 22:52 ART (2026-11-18 01:52:50Z) we made one paid call, `POST https://x402toll.com/v1/receipt/paycheck` with `{"salary":85000,"state":"TX"}`, 1.00 USDC on Base, settled in tx `0x34bf480da09593b18d24355b2f2ad223b48dfb2d32bbda79ffc998b8f1b703f3`. The response body is 3406 bytes, sha256 `892f464acd6fe65133f02d6f5173b3b2ee83e2e074dcfab4febfe0b95fcef474`. We then checked that one receipt.

Disclosure: the operator's spec credits us (GVP spec §6.3 rationale; response-provenance prior art in x402#3304). We wrote the verifier from the spec text with the published vectors in view, so this is a directed reproduction.

## Results (one receipt)

| Check | Result |
|---|---|
| V1 responseHash re-derives (GVP-FixedPoint/2) | pass |
| V3 receipt validates against schema/receipt.schema.json | pass |
| V2 Ed25519 signature vs key list from the origin | unverifiable without a mapping (run 1); verified under one assumed mapping H1 (run 2) |
| V4 payment on chain: 1.0 USDC payer to payTo, authorization nonce used | pass |
| V5 ERC-8004 agentId 59110 owner equals payTo | pass (identity binding only; says nothing about the answer) |
| V6 revocation list | not checked: spec §7 names no location; the receipt's recheckUrl is a verify endpoint |
| 8 controls on the real receipt, 7 negative and 1 positive, with H1 | all in the state written down beforehand |
| Second reading with golden-vector-provenance 0.12.0 | agrees on 7 of 7 cases (SECOND_READING_OUTPUT.txt) |

## The gap

The spec signs `issuer` as a string and `agentId` as a member. The receipt carries `issuer` as an object `{name, service, url}` and `agentId` only inside `onChainAnchor`. `signature.signed` names the members without saying where each comes from. The 0.12.0 package has no receipt-to-payload function. We fixed before paying that a mapping we could not read from the spec would be reported as unverifiable (run 1, `report_20261118T015258Z`: V2 unverifiable; the five signature controls could not be evaluated). After seeing the receipt we wrote one hypothesis down just before running it, H1: `issuer = issuer.service`, `agentId = onChainAnchor.agentId` (`mapping_H1.json`, run 2, `report_20261118T015428Z`). It verifies and the 8 controls land as expected. No other mapping was tried.

## Limits you should know

- One receipt, one day. Nothing here says the paycheck figures are right.
- The order of H1 (written, then run) rests on our statement: the addendum, `mapping_H1.json` and the run are within one second of each other and there is no external timestamp.
- The pre-registration was written before paying. `PREREGISTRO_PUBLIC.txt` is a redacted copy (operational details removed, see `REDACTIONS.txt`). The sha256 of the original at payment time was `7a94ffb4d28d3a21ad05bf0bf8c81ea8d8a7266a4996b000222b997b8b6fd726`; you cannot reproduce that hash from the redacted copy, so it is a commitment, not a proof.
- Spec used: `spec/gvp-0.2.md` from SolomonisBlack/golden-vector-provenance at commit `4c2aa528d19d9eac9f7fca32576f147dbeecf812`, file sha256 `0a06bdb0820e83fc2d42bde3bec1809c01d9888ee27d259cfc868887831a7ee4`. Key list from the origin, sha256 `ad54373f8a609bd716bac19ffd0cb48c48c036f69b5d2a0eafaf766c39044da2`.
- `SECOND_READING_OUTPUT.txt` transcribes what the operator saw in a terminal; nobody else sealed it.

## Re-run without us

1. Clone the upstream repo at the commit above; copy its `schema/` and `vectors/` next to these scripts.
2. The paid bytes are in `raw/paid_20261118T015250Z_*` and the receipt in `report_20261118T015428Z/receipt.json`. `python3 after_payment.py --mapping mapping_H1.json` re-runs V1 to V6 and the controls on the saved bytes (it fetches the live key list and queries a public Base RPC).
3. For the second reading, unpack golden-vector-provenance@0.12.0 into `npm_inspect/x/` (read it first; it has no dependencies and no install scripts) and run `npm_inspect/run_pkg_receipt.mjs` on `second_reading_input.json`.
4. `gvpverify.py.pre-e.bak` is the verifier before the one change we made before paying (require `fixedPointVersion` in /2 and /3 payloads, as the spec lists it).

The payment client is not published: it handles a signing key. It reads the 402 live, aborts if amount or network differ, and signs one EIP-3009 authorization for exactly the amount asked.
