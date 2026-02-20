import express, { Request, Response, NextFunction } from "express";
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
 * Request ID middleware
 * ------------------------------------------------------------
 */
app.use((req: Request, res: Response, next: NextFunction) => {
  const requestId = crypto.randomUUID();
  res.setHeader("x-solace-request-id", requestId);
  (req as any).solaceRequestId = requestId;
  next();
});

/**
 * ------------------------------------------------------------
 * Health
 * ------------------------------------------------------------
 */
app.get("/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    adapterId: cfg.adapterId,
  });
});

/**
 * ------------------------------------------------------------
 * Tenant authentication middleware
 * ------------------------------------------------------------
 */
async function requireTenant(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const orgId = String(req.header("x-solace-org-id") || "").trim();
  const apiKey = String(req.header("x-solace-api-key") || "").trim();

  if (!orgId || !apiKey) {
    return res.status(401).json({
      decision: "DENY",
      reason: "missing_x_solace_org_id_or_x_solace_api_key",
      requestId: (req as any).solaceRequestId,
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
      requestId: (req as any).solaceRequestId,
    });
  }

  if (!data || String(data.status || "").toLowerCase() !== "active") {
    return res.status(403).json({
      decision: "DENY",
      reason: "invalid_or_revoked_api_key",
      requestId: (req as any).solaceRequestId,
    });
  }

  // Non-blocking last_used update
  supabase
    .from("solace_api_keys")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", data.id)
    .then(() => {})
    .catch(() => {});

  (req as any).solaceTenant = {
    organizationId: orgId,
    apiKeyId: data.id,
  };

  next();
}

/**
 * ------------------------------------------------------------
 * Public Gate Endpoint
 * ------------------------------------------------------------
 */
app.post(
  "/v1/gate",
  requireTenant,
  express.json({ limit: "512kb" }),
  async (req: Request, res: Response) => {
    try {
      const result = await gateAndForward(cfg, req.body);

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
  }
);

/**
 * ------------------------------------------------------------
 * Optional authorize-only endpoint
 * ------------------------------------------------------------
 */
app.post(
  "/v1/authorize",
  express.json({ limit: "256kb" }),
  async (req: Request, res: Response) => {
    try {
      const result = await authorizeOnly(cfg, req.body);
      res.json(result);
    } catch (e) {
      res.status(500).json({
        decision: "DENY",
        reason: asMessage(e),
      });
    }
  }
);

export default app;
