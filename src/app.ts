import express from "express";
import crypto from "crypto";
import { loadAdapterConfigFromEnv } from "./config.js";
import { gateAndForwimport express from "express";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";
import { loadAdapterConfigFromEnv } from "./config.js";
import { gateAndForward, authorizeOnly } from "./gate.js";
import { asMessage } from "./errors.js";

const app = express();
const cfg = loadAdapterConfigFromEnv();

/**
 * ------------------------------------------------------------
 * Supabase (service role) for API key validation
 * ------------------------------------------------------------
 */
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_SERVICE_ROLE ||
  process.env.SUPABASE_SERVICE_KEY ||
  null;

if (!SUPABASE_URL) throw new Error("supabase_url_missing");
if (!SUPABASE_SERVICE_ROLE_KEY) throw new Error("supabase_service_role_key_missing");

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

/**
 * ------------------------------------------------------------
 * Request ID middleware (correlation)
 * ------------------------------------------------------------
 */
app.use((req, res, next) => {
  const requestId = crypto.randomUUID();
  (req as any).solaceRequestId = requestId;
  res.setHeader("x-solace-request-id", requestId);
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
 * Tenant auth middleware (public API access)
 * Required headers:
 *  - x-solace-org-id
 *  - x-solace-api-key
 * ------------------------------------------------------------
 */
async function requireTenant(req: any, res: any, next: any) {
  const orgId = String(req.header("x-solace-org-id") || "").trim();
  const apiKey = String(req.header("x-solace-api-key") || "").trim();

  if (!orgId || !apiKey) {
    return res.status(401).json({
      decision: "DENY",
      reason: "missing_x_solace_org_id_or_x_solace_api_key",
      requestId: req.solaceRequestId,
    });
  }

  const keyHash = crypto.createHash("sha256").update(apiKey).digest("hex");

  const { data, error } = await supabase
    .from("solace_api_keys")
    .select("id, organization_id, status")
    .eq("organization_id", orgId)
    .eq("key_hash", keyHash)
    .limit(1)
    .maybeSingle();

  if (error) {
    return res.status(503).json({
      decision: "DENY",
      reason: "api_key_lookup_failed",
      requestId: req.solaceRequestId,
    });
  }

  if (!data || String(data.status || "").toLowerCase() !== "active") {
    return res.status(403).json({
      decision: "DENY",
      reason: "invalid_or_revoked_api_key",
      requestId: req.solaceRequestId,
    });
  }

  // Optional: update last_used_at (non-blocking)
  supabase
    .from("solace_api_keys")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", data.id)
    .then(() => {})
    .catch(() => {});

  req.solaceTenant = { organizationId: orgId, apiKeyId: data.id };
  next();
}

/**
 * ------------------------------------------------------------
 * PUBLIC: Gate + Forward (the real runtime API)
 * ------------------------------------------------------------
 */
app.post("/v1/gate", requireTenant, express.json({ limit: "512kb" }), async (req, res) => {
  try {
    const envelope = req.body;

    const result = await gateAndForward(cfg, envelope);

    return res.status(200).json({
      ...result,
      requestId: (req as any).solaceRequestId,
    });
  } catch (e) {
    return res.status(500).json({
      decision: "DENY",
      reason: asMessage(e),
      requestId: (req as any).solaceRequestId,
    });
  }
});

/**
 * ------------------------------------------------------------
 * OPTIONAL: authorize-only (keep for internal testing)
 * If you want it public later, put requireTenant in front of it.
 * ------------------------------------------------------------
 */
app.post("/v1/authorize", express.json({ limit: "256kb" }), async (req, res) => {
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
ard, authorizeOnly } from "./gate.js";
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
