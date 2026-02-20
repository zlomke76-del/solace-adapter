// src/types.ts

// ------------------------------------------------------------
// JSON primitives (for hashing/canonicalization inputs)
// ------------------------------------------------------------
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject {
  [key: string]: JsonValue;
}

// ------------------------------------------------------------
// Intent / Execution Envelope
// ------------------------------------------------------------
export interface ActorRef {
  id: string;
}

/**
 * IMPORTANT:
 * Do NOT extend JsonObject here.
 * If ActionIntent extends JsonObject, every property must be JsonValue —
 * but ActorRef is not JsonValue, causing TS2411.
 */
export interface ActionIntent {
  actor: ActorRef;
  intent: string;

  context?: JsonObject;
  meta?: JsonObject;
}

/**
 * Execution payloads ARE JSON objects and may contain arbitrary fields.
 */
export type ExecutionPayload = {
  action?: string;
} & JsonObject;

export interface Acceptance {
  issuer: string;
  actorId: string;
  intent: string;
  executeHash: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;

  authorityKeyId?: string | null;
  authority_key_id?: string | null;
}

export interface GateRequestEnvelope {
  intent: ActionIntent;
  execute: ExecutionPayload;
  acceptance: Acceptance;
}

// ------------------------------------------------------------
// Core Client
// ------------------------------------------------------------
export interface CoreClientConfig {
  coreBaseUrl: string;
  timeoutMs: number;
  headers?: Record<string, string>;
}

export interface CoreAuthorizeResponse {
  decision: "PERMIT" | "DENY" | "ESCALATE";
  reason?: string;
  error?: string;
}

export interface CoreExecuteResponse {
  decision: "PERMIT" | "DENY" | "ESCALATE";
  reason?: string;

  executeHash?: string;
  intentHash?: string;

  issuedAt?: string;
  expiresAt?: string;
  time?: string;

  authorityKeyId?: string | null;
  error?: string;
}

// ------------------------------------------------------------
// Forwarding Targets
// ------------------------------------------------------------
export interface ForwardTarget {
  service: string;
  url: string;
  bearerToken?: string;
}

export interface AdapterForwardingConfig {
  adapterId: string;

  receiptPrivateKeyPem: string;
  receiptPublicKeyPem: string;
  receiptTtlSeconds?: number;
  clockSkewSeconds?: number;

  core: CoreClientConfig;

  // Prefix-routed services only
  targets: Record<string, ForwardTarget>;
}

// ------------------------------------------------------------
// Receipt
// ------------------------------------------------------------
export interface Receipt {
  v: number;

  receiptId: string;

  adapterId: string;
  service: string;

  actorId: string;
  intent: string;

  intentHash: string;
  executeHash: string;

  coreDecision: "PERMIT";
  authorityKeyId?: string | null;

  coreIssuedAt?: string;
  coreExpiresAt?: string;
  coreTime?: string;

  issuedAt: string;
  expiresAt: string;

  signature: string;
}

// ------------------------------------------------------------
// Gate Result
// ------------------------------------------------------------
export interface AdapterGateResult {
  decision: "PERMIT" | "DENY" | "ESCALATE";
  reason?: string;

  receipt?: Receipt;
  forwardStatus?: number;
  forwardBody?: unknown;

  executeHash?: string;
  intentHash?: string;
  authorityKeyId?: string | null;
}
