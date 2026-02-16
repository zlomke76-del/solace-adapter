// src/coreClient.ts

import type {
  CoreAuthorizeResponse,
  CoreClientConfig,
  CoreExecuteResponse,
  GateRequestEnvelope,
} from "./types.js";
import { FailClosedError } from "./errors.js";

// ------------------------------------------------------------
// Timeout helper
// ------------------------------------------------------------
function withTimeout(timeoutMs: number): { signal: AbortSignal; cancel: () => void } {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  return {
    signal: controller.signal,
    cancel: () => clearTimeout(t),
  };
}

// ------------------------------------------------------------
// Safe JSON parse
// ------------------------------------------------------------
async function safeJson(res: Response): Promise<any> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { _raw: text };
  }
}

// ------------------------------------------------------------
// Core Client
// ------------------------------------------------------------
export class SolaceCoreClient {
  private cfg: CoreClientConfig;

  constructor(cfg: CoreClientConfig) {
    if (!cfg?.coreBaseUrl) {
      throw new FailClosedError("missing_coreBaseUrl");
    }

    // Explicit defaulting (no duplicate keys)
    this.cfg = {
      coreBaseUrl: cfg.coreBaseUrl,
      timeoutMs: cfg.timeoutMs ?? 8000,
      headers: cfg.headers ?? {},
    };
  }

  private base(urlPath: string): string {
    const base = this.cfg.coreBaseUrl.replace(/\/+$/, "");
    const path = urlPath.startsWith("/") ? urlPath : `/${urlPath}`;
    return `${base}${path}`;
  }

  // ------------------------------------------------------------
  // /v1/authorize
  // ------------------------------------------------------------
  async authorize(intentObj: unknown): Promise<CoreAuthorizeResponse> {
    const { signal, cancel } = withTimeout(this.cfg.timeoutMs);

    try {
      const res = await fetch(this.base("/v1/authorize"), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...this.cfg.headers,
        },
        body: JSON.stringify(intentObj),
        signal,
      });

      // Any non-200 → treat as DENY (fail-closed)
      if (!res.ok) {
        return {
          decision: "DENY",
          reason: `core_http_${res.status}`,
        };
      }

      const data = await safeJson(res);

      if (!data || typeof data.decision !== "string") {
        return {
          decision: "DENY",
          reason: "core_malformed_response",
        };
      }

      return {
        decision: data.decision,
        reason:
          typeof data.reason === "string"
            ? data.reason
            : "core_reason_missing",
        error: typeof data.error === "string" ? data.error : undefined,
      };
    } catch {
      // Network failure → fail closed
      return {
        decision: "DENY",
        reason: "core_unreachable",
      };
    } finally {
      cancel();
    }
  }

  // ------------------------------------------------------------
  // /v1/execute
  // ------------------------------------------------------------
  async execute(envelope: GateRequestEnvelope): Promise<CoreExecuteResponse> {
    const { signal, cancel } = withTimeout(this.cfg.timeoutMs);

    try {
      const res = await fetch(this.base("/v1/execute"), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...this.cfg.headers,
        },
        body: JSON.stringify(envelope),
        signal,
      });

      // Core contract: typically returns 200 + decision
      // But if HTTP fails → fail closed.
      if (!res.ok) {
        return {
          decision: "DENY",
          reason: `core_http_${res.status}`,
        };
      }

      const data = await safeJson(res);

      if (!data || typeof data.decision !== "string") {
        return {
          decision: "DENY",
          reason: "core_malformed_response",
        };
      }

      return {
        decision: data.decision,
        reason:
          typeof data.reason === "string" ? data.reason : undefined,

        executeHash:
          typeof data.executeHash === "string"
            ? data.executeHash
            : undefined,

        intentHash:
          typeof data.intentHash === "string"
            ? data.intentHash
            : undefined,

        issuedAt:
          typeof data.issuedAt === "string"
            ? data.issuedAt
            : undefined,

        expiresAt:
          typeof data.expiresAt === "string"
            ? data.expiresAt
            : undefined,

        time:
          typeof data.time === "string"
            ? data.time
            : undefined,

        authorityKeyId:
          typeof data.authorityKeyId === "string" ||
          data.authorityKeyId === null
            ? data.authorityKeyId
            : undefined,

        error:
          typeof data.error === "string"
            ? data.error
            : undefined,
      };
    } catch {
      return {
        decision: "DENY",
        reason: "core_unreachable",
      };
    } finally {
      cancel();
    }
  }
}
