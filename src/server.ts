// src/server.ts
// Solace Adapter Gateway — Non-Bypassable Forwarding Mode
//
// Public endpoints:
//   GET  /health
//   POST /v1/authorize   (advisory passthrough to Core /v1/authorize)
//   POST /v1/gate        (NON-BYPASSABLE: calls Core /v1/execute, then forwards on PERMIT)
//
// Invariants:
// - Fail-closed for execution: if anything is ambiguous, return DENY and DO NOT forward.
// - Adapter is the only ingress for side effects.
// - Executors must verify adapter-signed receipt + executeHash binding.

import express from "express";
import crypto from "crypto";
import type { AdapterForwardingConfig, GateRequestEnvelope } from "./types";
import { loadAdapterConfigFromEnv } from "./config";
import { authorizeOnly, gateAndForward } from "./gate";
import { asMessage } from "./errors";

const app = express();

let CFG: AdapterForwardingConfig | null = null;

function nowIso(): string {
  return new Date().toISOString();
}

function sha256Hex(s: string): string {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function safeBodyPreview(body: any): string {
  try {
    const s = JSON.stringify(body);
    return s.length > 800 ? s.slice(0, 800) + "..." : s;
  } catch {
    return "[unserializable]";
  }
}

/**
 * ------------------------------------------------------------
 * Boot config
 * ------------------------------------------------------------
 */
function loadCfgOrDie(): AdapterForwardingConfig {
  if (CFG) return CFG;
  CFG = loadAdapterConfigFromEnv();
  return CFG;
}

try {
  loadCfgOrDie();
} catch (e) {
  // Deliberately crash on config error: fail-closed at deployment.
  console.error("[BOOT] config error:", asMessage(e));
  process.exit(1);
}

/**
 * ------------------------------------------------------------
 * Middleware
 * ------------------------------------------------------------
 */
app.use(express.json({ limit: "1mb" }));

// JSON parse error guard (fail-closed)
app.use((err: any, _req: any, res: any, next: any) => {
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    return res.status(400).json({
      decision: "DENY",
      reason: "invalid_json",
      message: err.message,
    });
  }
  next(err);
});

/**
 * ------------------------------------------------------------
 * Health check
 * ------------------------------------------------------------
 */
app.get("/health", (_req, res) => {
  const cfg = loadCfgOrDie();
  const core = cfg.core.coreBaseUrl;
  const actions = Object.keys(cfg.actionToService || {}).length;
  const targets = Object.keys(cfg.targets || {}).length;

  return res.status(200).json({
    status: "ok",
    service: "solace-adapter-gateway",
    mode: "forwarding-receipt",
    time: nowIso(),
    adapterId: cfg.adapterId,
    coreBaseUrl: core,
    actionRoutes: actions,
    targets,
  });
});

/**
 * ------------------------------------------------------------
 * POST /v1/authorize (advisory)
 * Passthrough to Core /v1/authorize
 * IMPORTANT: This is NOT execution authority.
 * ------------------------------------------------------------
 */
app.post("/v1/authorize", async (req, res) => {
  const cfg = loadCfgOrDie();
  try {
    const out = await authorizeOnly(cfg, req.body);
    // always 200, decision in body
    return res.status(200).json(out);
  } catch (e) {
    // fail-closed: treat as DENY
    return res.status(200).json({
      decision: "DENY",
      reason: "adapter_authorize_error",
      error: asMessage(e),
    });
  }
});

/**
 * ------------------------------------------------------------
 * POST /v1/gate (NON-BYPASSABLE)
 * This endpoint is the only public ingress for side effects.
 *
 * Body must contain:
 *   { intent, execute, acceptance, route? }
 *
 * NOTE:
 * - route is OPTIONAL in this reference implementation.
 * - service selection is derived from execute.action via cfg.actionToService.
 * ------------------------------------------------------------
 */
app.post("/v1/gate", async (req, res) => {
  const cfg = loadCfgOrDie();
  const startedAt = nowIso();

  // Fail-closed default
  try {
    const body = req.body as GateRequestEnvelope;

    if (!body || !body.intent || !body.execute || !body.acceptance) {
      return res.status(200).json({
        decision: "DENY",
        reason: "invalid_or_missing_gate_request",
      });
    }

    const result = await gateAndForward(cfg, body);

    // If PERMIT, forwarding already happened (or failed with DENY)
    return res.status(200).json({
      ...result,
      time: startedAt,
    });
  } catch (e) {
    // Never forward on error; return DENY
    const errMsg = asMessage(e);
    console.error("[GATE] error:", errMsg, "body:", safeBodyPreview(req.body));

    return res.status(200).json({
      decision: "DENY",
      reason: "adapter_gate_error",
      error: errMsg,
    });
  }
});

/**
 * ------------------------------------------------------------
 * Hard fail-closed catch-all
 * ------------------------------------------------------------
 */
app.use((_req, res) => {
  return res.status(404).json({
    decision: "DENY",
    reason: "not_found",
  });
});

/**
 * ------------------------------------------------------------
 * Start
 * ------------------------------------------------------------
 */
const PORT = process.env.PORT ? Number(process.env.PORT) : 8080;
app.listen(PORT, () => {
  const cfg = loadCfgOrDie();
  const cfgHash = sha256Hex(
    JSON.stringify({
      adapterId: cfg.adapterId,
      coreBaseUrl: cfg.core.coreBaseUrl,
      receiptTtlSeconds: cfg.receiptTtlSeconds,
      clockSkewSeconds: cfg.clockSkewSeconds,
      actionRoutes: Object.keys(cfg.actionToService || {}),
      targets: Object.keys(cfg.targets || {}),
    })
  );

  console.log("[BOOT] solace-adapter-gateway listening");
  console.log("[BOOT] port:", PORT);
  console.log("[BOOT] adapterId:", cfg.adapterId);
  console.log("[BOOT] coreBaseUrl:", cfg.core.coreBaseUrl);
  console.log("[BOOT] configFingerprint:", cfgHash);
});
