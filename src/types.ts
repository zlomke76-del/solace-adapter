// src/types.ts

export type Decision = "PERMIT" | "DENY" | "ESCALATE";

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [k: string]: JsonValue };

export type JsonObject = { [k: string]: JsonValue };

export interface ActorRef {
  id: string;
}

export interface Intent extends JsonObject {
  actor: ActorRef;
  intent: string; // authoritative identifier (string)
  context?: JsonObject;
}

export interface ExecutePayload extends JsonObject {
  action: string;
  target?: string;
}

export interface Acceptance {
  issuer: string;
  actorId: string;
  intent: string;
  executeHash: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;

  // Optional registry key binding (preferred)
  authorityKeyId?: string;
  authority_key_id?: string;
}

export interface CoreAuthorizeResponse {
  decision: Decision;
  reason: string;
}

export interface CoreExecuteResponse {
  decision: Decision;
  reason?: string;

  executeHash?: string;
  intentHash?: string;

  issuedAt?: string;
  expiresAt?: string;

  time?: string;
  authorityKeyId?: string | null;

  error?: string;
}

export interface CoreClientConfig {
  coreBaseUrl: string; // e.g. https://solace-core-authority.vercel.app
  timeoutMs?: number; // default 8000
  headers?: Record<string, string>;
}

export interface ForwardTarget {
  // A logical name for the downstream executor (used in receipts + logging)
  service: string;

  // Absolute URL to the executor entrypoint that actually performs the side effect.
  // Example: https://payments-executor.yourco.com/v1/execute
  url: string;

  // Optional shared secret header for network-layer hardening.
  // This is NOT a substitute for receipt verification; it’s an extra belt.
  bearerToken?: string;
}

export interface AdapterForwardingConfig {
  adapterId: string; // stable identifier for the adapter deployment (e.g. "adapter-prod-us1")
  receiptPrivateKeyPem: string; // PEM private key used to sign receipts (Ed25519 recommended)
  receiptPublicKeyPem: string; // PEM public key used by executors to verify receipts
  receiptTtlSeconds?: number; // default 30
  clockSkewSeconds?: number; // default 10

  core: CoreClientConfig;

  // Map action->target service.
  // You can also implement your own router, but this keeps the reference impl minimal.
  actionToService: Record<string, string>;
  targets: Record<string, ForwardTarget>;
}

export interface GateRequestEnvelope {
  intent: Intent;
  execute: ExecutePayload;
  acceptance: Acceptance;
}

export interface Receipt {
  // Receipt schema is stable and intentionally small.
  v: 1;
  receiptId: string;
  adapterId: string;
  service: string;

  actorId: string;
  intent: string;
  executeHash: string;

  // Evidence carried forward from Core decision
  intentHash: string;
  coreDecision: "PERMIT";
  coreIssuedAt?: string;
  coreExpiresAt?: string;
  coreTime?: string;
  authorityKeyId?: string | null;

  // Receipt window
  issuedAt: string;
  expiresAt: string;

  // Signature over canonical material (excluding signature)
  signature: string;
}

export interface AdapterGateResult {
  decision: Decision;
  reason: string;

  // present only if PERMIT and forwarding succeeded
  receipt?: Receipt;
  forwardStatus?: number;
  forwardBody?: JsonValue;

  // hashes for debugging / trace
  executeHash?: string;
  intentHash?: string;
  authorityKeyId?: string | null;
}
