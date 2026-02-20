import express, { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { createRequire } from "module";
import { createClient } from "@supabase/supabase-js";
import { loadAdapterConfigFromEnv } from "./config.js";
import { gateAndForward, authorizeOnly } from "./gate.js";
import { asMessage } from "./errors.js";

/**
 * ------------------------------------------------------------
 * Proper CJS import for express-rate-limit under NodeNext
 * ------------------------------------------------------------
 */
const require = createRequire(import.meta.url);
const rateLimit = require("express-rate-limit");

const app = express();
const cfg = loadAdapterConfigFromEnv();

/**
 * ------------------------------------------------------------
 * Supabase (service role)
 * ------------------------------------------------------------
 */
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_SERVICE_ROLE ||
  process.env.SUPABASE_SERVICE_KEY ||
  null;

if (!SUPABASE_URL) throw new Error("supabase_url_missing");
if (!SUPABASE_SERVICE_ROLE_KEY)
  throw new Error("supabase_service_role_key_missing");

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
app.get("/health", async (_req: Request, res: Response) => {
  const { error } = await supabase
    .from("solace_api_keys")
    .select("id")
    .limit(1);

  res.json({
    status: "ok",
    adapterId: cfg.adapterId,
    supabaseConnected: !error,
    supabaseError: error?.message || null,
  });
});

/**
 * ------------------------------------------------------------
 * Public API Info
 * ------------------------------------------------------------
 */
app.get("/v1/info", (_req: Request, res: Response) => {
  res.json({
    version: "v1",
    rateLimit: {
      windowSeconds: Number(process.env.SOLACE_RATE_LIMIT_WINDOW_SECONDS || 60),
      maxRequests: Number(process.env.SOLACE_RATE_LIMIT_MAX || 100),
    },
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
  const apiKeyRaw = String(req.header("x-solace-api-key") || "");

  if (!orgId || !apiKeyRaw) {
    return res.status(401).json({
      decision: "DENY",
      reason: "missing_x_solace_org_id_or_x_solace_api_key",
      requestId: (req as any).solaceRequestId,
    });
  }

  const apiKey = apiKeyRaw.trim();
  const keyHash = crypto
    .createHash("sha256")
    .update(apiKey, "utf8")
    .digest("hex");

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

  (req as any).solaceTenant = {
    organizationId: orgId,
    apiKeyId: data.id,
  };

  next();
}

/**
 * ------------------------------------------------------------
 * Per-Tenant Rate Limiter
 * ------------------------------------------------------------
 */
const tenantRateLimiter = rateLimit({
  windowMs:
    Number(process.env.SOLACE_RATE_LIMIT_WINDOW_SECONDS || 60) * 1000,
  max: Number(process.env.SOLACE_RATE_LIMIT_MAX || 100),
  keyGenerator: (req: Request) =>
    (req as any).solaceTenant?.organizationId || "unknown",
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    res.status(429).json({
      decision: "DENY",
      reason: "rate_limit_exceeded",
      requestId: (req as any).solaceRequestId,
    });
  },
});

/**
 * ------------------------------------------------------------
 * Gate Endpoint
 * ------------------------------------------------------------
 */
app.post(
  "/v1/gate",
  requireTenant,
  tenantRateLimiter,
  express.json({ limit: "512kb" }),
  async (req: Request, res: Response) => {
    try {
      const result = await gateAndForward(cfg, req.body);

      if (result.decision !== "PERMIT") {
        return res.status(403).json({
          ...result,
          requestId: (req as any).solaceRequestId,
        });
      }

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
 * Authorize-only endpoint
 * ------------------------------------------------------------
 */
app.post(
  "/v1/authorize",
  requireTenant,
  tenantRateLimiter,
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
