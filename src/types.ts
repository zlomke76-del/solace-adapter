// src/types.ts

/* -------------------------------------------------------
 * Base JSON (loose on purpose: adapter forwards arbitrary
 * execution payloads; strict typing here causes TS2411 churn)
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
  intent: string;            // authoritative intent string identifier
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
  coreBaseUrl: string;                 // e.g. https://solace-core.vercel.app
  executePath?: string;                // default /v1/execute
  authorizePath?: string;              // default /v1/authorize
  timeoutMs?: number;                  // default 10_000
  headers?: Record<string, string>;    // adapter->core shared secret header etc.
}

export type CoreDecision = "PERMIT" | "DENY" | "ESCALATE";

export interface CoreAuthorizeResponse {
  decision: CoreDecision;
  reason?: string;
}

export interface CoreExecuteResponse {
  decision: "PERMIT" | "DENY";
  reason?: string;

  executeHash?: string;
  intentHash?: string;

  // Core returns these in your server.js PERMIT response
  issuedAt?: string;
  expiresAt?: string;
  time?: string;

  authorityKeyId?: string | null;
}

/* -------------------------------------------------------
 * Forwarding config
 * ----------------------------------------------------- */

export interface ForwardTarget {
  service: string;                      // logical executor service name
  url: string;                          // executor endpoint (ideally private)
  method?: "POST" | "PUT";
  timeoutMs?: number;
  headers?: Record<string, string>;     // optional adapter->executor auth
}

export interface AdapterForwardingConfig {
  adapterId: string;

  // Receipt signing keys
  receiptPrivateKeyPem: string;         // PEM private key used to sign receipts
  receiptPublicKeyPem: string;          // PEM public key used by executors to verify
  receiptTtlSeconds: number;            // receipt validity window

  // Core config lives under `core` in your gate.ts
  core: CoreClientConfig;

  // Map intent.intent -> service name
  actionToService: Record<string, string>;

  // Service registry: service name -> target
  services: Record<string, ForwardTarget>;
}

/* -------------------------------------------------------
 * Receipt (adapter-signed execution authorization proof)
 * ----------------------------------------------------- */

export interface Receipt {
  v: number;                            // receipt schema version
  receiptId: string;                    // uuid
  adapterId: string;

  service: string;                      // which executor was selected
  actorId: string;
  intent: string;

  intentHash: string;
  executeHash: string;

  coreDecision: "PERMIT";               // receipt only minted on PERMIT
  coreTime?: string;
  coreIssuedAt?: string;
  coreExpiresAt?: string;

  issuedAt: string;
  expiresAt: string;

  signature: string;                    // base64 signature over canonical receipt material
}

/* -------------------------------------------------------
 * Gate result (what gate.ts returns)
 * ----------------------------------------------------- */

export interface AdapterGateResult {
  decision: "PERMIT" | "DENY";
  reason?: string;

  service?: string;
  receipt?: Receipt;

  // Optional: include upstream core decision info for logging/debug
  core?: CoreExecuteResponse;
}
