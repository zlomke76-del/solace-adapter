// src/types.ts

/* -------------------------------------------------------
 * Loose JSON (adapter forwards arbitrary payloads)
 * ----------------------------------------------------- */

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonArray;

export interface JsonObject {
  [key: string]: any;
}

export interface JsonArray extends Array<JsonValue> {}

/* -------------------------------------------------------
 * Intent / Envelope
 * ----------------------------------------------------- */

export interface ActorRef {
  id: string;
}

export interface IntentObject {
  intent: string;
  actor: ActorRef;
  context?: JsonObject;
  [k: string]: any;
}

export interface GateRequestEnvelope {
  intent: IntentObject;
  execute: JsonObject;
  acceptance: JsonObject;
}

/* -------------------------------------------------------
 * Core client config + responses
 * ----------------------------------------------------- */

export interface CoreClientConfig {
  coreBaseUrl: string;
  executePath?: string;
  authorizePath?: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
}

export type CoreDecision = "PERMIT" | "DENY" | "ESCALATE";

export interface CoreAuthorizeResponse {
  decision: CoreDecision;
  reason?: string;
  error?: string;
}

export interface CoreExecuteResponse {
  decision: "PERMIT" | "DENY";
  reason?: string;
  error?: string;

  executeHash?: string;
  intentHash?: string;

  issuedAt?: string;
  expiresAt?: string;
  time?: string;

  authorityKeyId?: string | null;
}

/* -------------------------------------------------------
 * Forward targets
 * ----------------------------------------------------- */

export interface ForwardTarget {
  service: string;
  url: string;
  method?: "POST" | "PUT";
  timeoutMs?: number;
  headers?: Record<string, string>;

  // Your config.ts is passing this:
  bearerToken?: string;
}

/* -------------------------------------------------------
 * Adapter config
 * ----------------------------------------------------- */

export interface AdapterForwardingConfig {
  adapterId: string;

  receiptPrivateKeyPem: string;
  receiptPublicKeyPem: string;
  receiptTtlSeconds: number;

  clockSkewSeconds?: number;

  core: CoreClientConfig;

  // Your gate.ts is referencing `targets`
  targets: Record<string, ForwardTarget>;

  // Intent string -> service key
  actionToService: Record<string, string>;
}

/* -------------------------------------------------------
 * Receipt
 * ----------------------------------------------------- */

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
  coreTime?: string;
  coreIssuedAt?: string;
  coreExpiresAt?: string;

  authorityKeyId?: string | null;

  issuedAt: string;
  expiresAt: string;

  signature: string;
}

/* -------------------------------------------------------
 * Gate result
 * ----------------------------------------------------- */

export interface AdapterGateResult {
  decision: "PERMIT" | "DENY";
  reason?: string;

  service?: string;
  receipt?: Receipt;

  forwardStatus?: number;

  core?: CoreExecuteResponse;
}
