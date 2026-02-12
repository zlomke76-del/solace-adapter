// src/types.ts

// ------------------------------------------------------------
// JSON primitives
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

export interface ActionIntent extends JsonObject {
  actor: ActorRef;
  intent: string;
  context?: JsonObject;
}

export interface ExecutionPayload extends JsonObject {
  action?: string;
}

export interface Acceptance {
  issuer: string;
  actorId: string;
  intent: string;
  executeHash: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;
  authorityKeyId?: string | null;
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

  actionToService: Record<string, string>;
  targets: Record<string, ForwardTarget>;
}

// ------------------------------------------------------------
// Receipt
// ------------------------------------------------------------
export interface Receipt {
  v: number;
  adapterId: string;
  service: string;
  actorId: string;
  intent: string;
  intentHash: string;
  executeHash: string;
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
