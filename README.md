Solace Adapter

Provider-agnostic Policy Enforcement Point (PEP)
Fail-closed execution gate that forwards side effects only after Solace Core returns PERMIT and binds execution to a short-lived cryptographic receipt.

🔒 Architectural Role

The Adapter is the runtime control plane between AI systems and side-effect executors.

It enforces:

Deterministic PERMIT/DENY from Solace Core

Cryptographic receipt binding

Service isolation

Short-TTL replay resistance

Hash-bound execution integrity

It does not make policy decisions.
It enforces them.

Enforcement Guarantees

The Adapter guarantees:

❌ No forwarding on DENY

❌ No forwarding on Core error

❌ No forwarding if receipt minting fails

❌ No forwarding without a valid authorityKeyId

❌ No forwarding if ledger write fails at Core boundary

Forwarding occurs only after:

Core verifies signature (Ed25519)

Core validates authority key status + window

Core enforces intent scope + thresholds

Core enforces execution_constraints from bound schema

Core binds schema receipt ID + schema hash into ledger evidence

Core returns PERMIT

Modes
1️⃣ HTTP Gateway (Drop-In)

Run as sidecar / gateway.

Required environment:

SOLACE_CORE_URL
SOLACE_ADAPTER_RECEIPT_PRIVATE_KEY_PEM
SOLACE_ADAPTER_RECEIPT_PUBLIC_KEY_PEM


Exposes:

POST /v1/gate


Request:

{
  "intent": { "...": "..." },
  "execute": { "...": "..." },
  "acceptance": { "...": "..." }
}


Behavior:

Validates envelope structure

Routes execute.action → configured service

Calls Solace Core /v1/execute

Fail-closes unless decision === PERMIT

Mints short-lived signed receipt

Forwards request + receipt to executor

Receipt Binding

Each forwarded execution includes:

x-solace-receipt: base64(JSON receipt)


Receipt contains:

adapterId

service

actorId

intent

executeHash

intentHash

authorityKeyId

issuedAt

expiresAt

receiptId

signature (Ed25519)

Receipts are:

Short-lived (default 30 seconds)

Service-scoped

Hash-bound

Cryptographically signed

Executor Requirements (MANDATORY)

Executors MUST verify receipt before performing side effects.

Verification must include:

Decode x-solace-receipt

Verify Ed25519 signature

Enforce TTL window

Verify receipt.service === expectedService

Recompute executeHash

Compare to receipt.executeHash

Enforce idempotency on receiptId or executeHash

If any check fails → reject execution.

Failure to implement this makes the adapter bypassable.

Network Boundary Requirements

For production deployments:

Executor must not expose public ingress.

Only Adapter identity should reach executor (private networking or mTLS).

Adapter must not expose internal executor route publicly.

Cryptographic verification is mandatory.
Network isolation is defense-in-depth.

Fail-Closed Behavior

Adapter never retries on DENY.

Adapter never auto-permits.

Adapter never caches PERMIT decisions.

Every execution request requires a fresh Core decision.

Threat Model

Without executor verification, Adapter becomes controlled forwarding, not enforcement.

With receipt verification:

Direct executor calls fail.

Payload mutation fails (executeHash mismatch).

Cross-service replay fails.

Expired receipt fails.

Schema constraint violations fail.

Authority key revocation propagates via Core.

Trust Boundary Diagram

AI → Adapter → Core → Ledger
      ↓
    Executor (verifies receipt)

No receipt → no execution.

Summary

Solace Adapter is not middleware.

It is a cryptographic enforcement boundary between intent authorization and side effects.

Side effects occur only when:

Authority key is valid

Signature is valid

Schema constraints pass

Core binds decision to ledger

Adapter mints receipt

Executor verifies receipt

Otherwise → DENY.

🔎 Security Review Checklist

This checklist is intended for security teams, compliance auditors, and architecture review boards.

Adapter Boundary

 Adapter fails closed on any Core decision ≠ PERMIT

 Adapter never forwards without a valid Core response

 Adapter does not cache PERMIT decisions

 Adapter mints short-TTL signed receipts per execution

 Adapter binds executeHash and intentHash into receipt

Core Authority

 Core verifies Ed25519 acceptance signatures

 Authority keys are validated for:

active status

validity window

intent scope

optional threshold limits

 Core enforces execution_constraints from latest exported schema

 Schema identity (receipt_id + schema_hash) is bound into ledger evidence

 Ledger write is required for PERMIT (fail-closed if insert fails)

Executor Enforcement

 Executor rejects requests without x-solace-receipt header

 Executor verifies receipt signature using adapter public key

 Executor enforces receipt TTL window

 Executor verifies receipt.service matches expected service

 Executor recomputes executeHash and compares to receipt

 Executor enforces idempotency (receiptId or executeHash unique constraint)

 Executor performs side effects only after successful verification

Network Controls (Defense-in-Depth)

 Executor endpoint is not publicly exposed

 Adapter-to-executor communication occurs over private networking or mTLS

 Adapter private key is securely stored (KMS or equivalent)

 Core service role key is not exposed outside trusted runtime

🔄 Minimal Runtime Sequence Diagram
AI System
   |
   |  intent + execute + acceptance
   v
Solace Adapter (PEP)
   |
   |-- POST /v1/execute -------------------->
   |                                         |
   |                                  Solace Core
   |                                         |
   |   - Verify signature                   |
   |   - Validate authority key             |
   |   - Enforce execution_constraints      |
   |   - Bind schema receipt + hash         |
   |   - Write ledger record                |
   |                                         |
   |<--------------------- PERMIT / DENY ---|
   |
   | (if PERMIT)
   |  - Mint short-TTL signed receipt
   |  - Bind executeHash + intentHash
   v
Executor Service
   |
   |  - Verify receipt signature
   |  - Enforce TTL
   |  - Verify service binding
   |  - Recompute executeHash
   |  - Enforce idempotency
   |
   v
Side Effect (e.g., refund issued)
No PERMIT → no receipt → no execution.

🏛 Enterprise Control Statement

For enterprise review documentation, add this section.

Control Objective

Ensure that AI-driven side effects occur only when explicitly authorized under cryptographically verifiable authority, with full audit traceability.

Control Mechanism

Solace enforces a multi-layer authority boundary:

Cryptographic Acceptance — Human or system principal signs intent acceptance using Ed25519.

Registry Validation — Core verifies authority key status, validity window, and scope.

Schema Enforcement — Core enforces organization-specific execution constraints.

Immutable Evidence Binding — Core writes decision record bound to schema receipt hash.

Policy Enforcement Point — Adapter blocks forwarding unless PERMIT is returned.

Receipt-Based Execution Gate — Executor verifies signed receipt and payload integrity.

Replay Resistance — Short TTL + idempotency enforcement prevent duplicate execution.

This architecture prevents:

Direct executor invocation bypass

Payload mutation after authorization

Cross-service receipt replay

Authority key misuse outside validity window

Execution under outdated schema without binding evidence

🔐 Formal Enforcement Statement

The Solace Adapter is not middleware.
It is a cryptographic enforcement boundary.

Execution is possible only when:

Acceptance signature is valid

Authority key is active and within validity window

Intent scope permits execution

Execution constraints evaluate true

Schema receipt identity is bound to evidence

Ledger write succeeds

Adapter mints receipt

Executor verifies receipt and payload integrity

Otherwise, execution is denied.

