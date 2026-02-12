export type SolaceDecision = "PERMIT" | "DENY" | "ESCALATE";

export type ExecuteEnvelope = {
  intent: any;      // semantic intent object (provider-agnostic)
  execute: any;     // exact execution payload (hashable)
  acceptance?: any; // optional signed artifact (usually required for PERMIT)
};

export type CoreExecuteResponse =
  | { decision: "PERMIT"; executeHash?: string; intentHash?: string; issuedAt?: string; expiresAt?: string; [k: string]: any }
  | { decision: "DENY"; reason: string; [k: string]: any }
  | { decision: "ESCALATE"; reason: string; [k: string]: any };

export type AdapterConfig = {
  coreBaseUrl: string;          // e.g. https://solace-core.yourdomain.com
  coreExecutePath?: string;     // default /v1/execute
  coreAuthorizePath?: string;   // default /v1/authorize (optional)
  timeoutMs?: number;           // default 4000
  requirePermit?: boolean;      // default true
};
