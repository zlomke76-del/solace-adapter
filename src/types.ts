// src/types.ts

/* -------------------------------------------------------
 * Base JSON Types
 * ----------------------------------------------------- */

export type JsonPrimitive = string | number | boolean | null;

export type JsonValue =
  | JsonPrimitive
  | JsonObject
  | JsonArray;

export interface JsonObject {
  [key: string]: any; // intentionally relaxed for execution envelopes
}

export interface JsonArray extends Array<JsonValue> {}

/* -------------------------------------------------------
 * Intent + Gate Structures
 * ----------------------------------------------------- */

export interface ActorRef {
  id: string;
}

export interface IntentObject {
  intent: string;
  actor: ActorRef;
  context?: JsonObject;
}

export interface GateRequestEnvelope {
  intent: IntentObject;
  execute: JsonObject;
  acceptance: JsonObject;
}

/* -------------------------------------------------------
 * Core Client Types
 * ----------------------------------------------------- */

export interface CoreClientConfig {
  baseUrl: string;
  executePath?: string;
  authorizePath?: string;
  apiKey?: string;
  timeoutMs?: number;
}

export interface CoreAuthorizeResponse {
  decision: "PERMIT" | "DENY" | "ESCALATE";
  reason?: string;
}

export interface CoreExecuteResponse {
  decision: "PERMIT" | "DENY";
  reason?: string;
  executeHash?: string;
  intentHash?: string;
  authorityKeyId?: string | null;
}

/* -------------------------------------------------------
 * Forwarding + Adapter Config
 * ----------------------------------------------------- */

export interface ForwardTarget {
  name: string;
  url: string;
  method?: "POST" | "PUT";
  timeoutMs?: number;
}

export interface AdapterForwardingConfig {
  targets: ForwardTarget[];
  adapterSigningKeyPem: string;
  adapterId: string;
}

/* -------------------------------------------------------
 * Gate Results
 * ----------------------------------------------------- */

export interface AdapterGateResult {
  permitted: boolean;
  receipt?: Receipt;
  reason?: string;
}

/* -------------------------------------------------------
 * Receipt
 * ----------------------------------------------------- */

export interface Receipt {
  adapterId: string;
  executeHash: string;
  intentHash: string;
  issuedAt: string;
  signature: string;
}
