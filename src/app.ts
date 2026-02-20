import express from "express";
import crypto from "crypto";
import { loadAdapterConfigFromEnv } from "./config.js";
import { gateAndForward, authorizeOnly } from "./gate.js";
import { asMessage } from "./errors.js";
import { createClient } from "@supabase/supabase-js";

const app = express();
const cfg = loadAdapterConfigFromEnv();

/**
 * ------------------------------------------------------------
 * Supabase (for multi-tenant API key auth)
 * ------------------------------------------------------------
 */
const SUPABASE_URL = process.env.SUPABASE_URL!;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY!;
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

/**
 * ------------------------------------------------------------
 * Middleware: Request ID
 * ------------------------------------------------------------
 */
app.use((req, res, next) => {
  const requestId = crypto.randomUUID();
  res.setHeader("x-solace-request-id", requestId);
  (req as any).requestId = requestId;
  next();
});

/**
 * ------------------------------------------------------------
 * Health
 * ------------------------------------------------------------
 */
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    adapterId: cfg.adapterId,
  });
});

/**
 * ------------------------------------------------------------
 * Middleware: Multi-Tenant API Key Auth
 * ------------------------------------------------------------
 */
async function authenticateTenant(req: any, res: any, next: any) {
  const orgId = req.header("x-solace-org-id");
  const apiKey = req.header("x-solace-api-key");

  if (!orgId || !apiKey) {
    return res.status(401).json({
      decision: "DENY",
      reason: "missing_auth_headers",
    });
  }

  const keyHash = crypto.createHash("sha256").update(apiKey).digest("hex");

  const { data, error } = await supabase
    .from("solace_api_keys")
    .select("organization_id, status")
    .eq("organization_id", orgId)
    .eq("key_hash", keyHash)
    .limit(1)
    .maybeSingle();

  if (error || !data || data.status !== "active") {
    return res.status(403).json({
      decision: "DENY",
      reason: "invalid_api_key",
    });
  }

  req.tenantOrgId = orgId;
  next();
}

/**
 * ------------------------------------------------------------
 * Public Runtime Gate (Enforcement Boundary)
 * ------------------------------------------------------------
 */
app.post(
  "/v1/gate",
  authenticateTenant,
  express.json({ limit: "512kb" }),
  async (req, res) => {
    try {
      const envelope = req.body;

      const result = await gateAndForward(cfg, envelope);

      return res.status(200).json(result);
    } catch (e) {
      return res.status(500).json({
        decision: "DENY",
        reason: asMessage(e),
      });
    }
  }
);

/**
 * ------------------------------------------------------------
 * Optional: Authorize-only endpoint (internal / testing)
 * ------------------------------------------------------------
 */
app.post("/v1/authorize", express.json(), async (req, res) => {
  try {
    const result = await authorizeOnly(cfg, req.body);
    res.json(result);
  } catch (e) {
    res.status(500).json({
      decision: "DENY",
      reason: asMessage(e),
    });
  }
});

export default app;
