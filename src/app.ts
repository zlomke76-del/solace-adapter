// src/app.ts

import express, { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { createRequire } from "module";
import { createClient } from "@supabase/supabase-js";
import { loadAdapterConfigFromEnv } from "./config.js";
import { gateAndForward, authorizeOnly } from "./gate.js";
import { SolaceCoreClient } from "./coreClient.js";
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

function isLikelyUuid(v: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    String(v || "")
  );
}

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
  const { error } = await supabase.from("solace_api_keys").select("id").limit(1);

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
 * Public Registration Endpoint (Enterprise Intake)
 * ------------------------------------------------------------
 */
app.post(
  "/v1/register",
  express.json({ limit: "256kb" }),
  async (req: Request, res: Response) => {
    try {
      const {
        legal_name,
        legal_entity_type,
        jurisdiction,
        registration_id,
        contact_email,
        use_case,
        environment,
        public_key,
      } = req.body || {};

      if (
        !legal_name ||
        !legal_entity_type ||
        !jurisdiction ||
        !contact_email ||
        !use_case ||
        !environment ||
        !public_key
      ) {
        return res.status(400).json({
          status: "error",
          reason: "missing_required_fields",
        });
      }

      if (!["staging", "production"].includes(environment)) {
        return res.status(400).json({
          status: "error",
          reason: "invalid_environment",
        });
      }

      if (!String(public_key).includes("BEGIN PUBLIC KEY")) {
        return res.status(400).json({
          status: "error",
          reason: "invalid_public_key_format",
        });
      }

      const { data, error } = await supabase
        .from("solace_client_registrations")
        .insert({
          legal_name,
          legal_entity_type,
          jurisdiction,
          registration_id: registration_id || null,
          contact_email,
          use_case,
          environment,
          requested_public_key: public_key,
          status: "pending",
        })
        .select("id, status")
        .single();

      if (error) {
        return res.status(500).json({
          status: "error",
          reason: "registration_insert_failed",
          detail: error.message,
        });
      }

      return res.status(201).json({
        status: "submitted",
        registration_id: data.id,
        review_status: data.status,
      });
    } catch (e) {
      return res.status(500).json({
        status: "error",
        reason: asMessage(e),
      });
    }
  }
);

/**
 * ------------------------------------------------------------
 * Admin Approval Endpoint (creates org + authority key + api key)
 * Protected by SOLACE_ADMIN_TOKEN
 *
 * Required env:
 *   SOLACE_ADMIN_TOKEN
 *   SOLACE_ADMIN_PRINCIPAL_ID   (existing principal UUID)
 * ------------------------------------------------------------
 */
app.post(
  "/v1/admin/approve",
  express.json({ limit: "128kb" }),
  async (req: Request, res: Response) => {
    try {
      const auth = String(req.header("authorization") || "");
      const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

      const expected = String(process.env.SOLACE_ADMIN_TOKEN || "").trim();
      if (!expected || !token || token !== expected) {
        return res.status(401).json({
          status: "error",
          reason: "unauthorized",
          requestId: (req as any).solaceRequestId,
        });
      }

      const adminPrincipalId = String(
        process.env.SOLACE_ADMIN_PRINCIPAL_ID || ""
      ).trim();
      if (!isLikelyUuid(adminPrincipalId)) {
        return res.status(500).json({
          status: "error",
          reason: "missing_or_invalid_SOLACE_ADMIN_PRINCIPAL_ID",
          requestId: (req as any).solaceRequestId,
        });
      }

      const registrationId = String(req.body?.registration_id || "").trim();
      if (!isLikelyUuid(registrationId)) {
        return res.status(400).json({
          status: "error",
          reason: "invalid_registration_id",
          requestId: (req as any).solaceRequestId,
        });
      }

      // Load registration
      const { data: reg, error: regErr } = await supabase
        .from("solace_client_registrations")
        .select("*")
        .eq("id", registrationId)
        .maybeSingle();

      if (regErr) {
        return res.status(503).json({
          status: "error",
          reason: "registration_lookup_failed",
          detail: regErr.message,
          requestId: (req as any).solaceRequestId,
        });
      }

      if (!reg) {
        return res.status(404).json({
          status: "error",
          reason: "registration_not_found",
          requestId: (req as any).solaceRequestId,
        });
      }

      if (String(reg.status) !== "pending") {
        return res.status(400).json({
          status: "error",
          reason: "registration_not_pending",
          current_status: reg.status,
          requestId: (req as any).solaceRequestId,
        });
      }

      if (!reg.requested_public_key) {
        return res.status(400).json({
          status: "error",
          reason: "missing_requested_public_key",
          requestId: (req as any).solaceRequestId,
        });
      }

      // 1) Create organization
      const { data: org, error: orgErr } = await supabase
        .from("solace_organizations")
        .insert({
          legal_name: reg.legal_name,
          legal_entity_type: reg.legal_entity_type,
          jurisdiction: reg.jurisdiction,
          registration_id: reg.registration_id,
          status: "active",
        })
        .select("id")
        .single();

      if (orgErr || !org) {
        return res.status(500).json({
          status: "error",
          reason: "org_create_failed",
          detail: orgErr?.message || null,
          requestId: (req as any).solaceRequestId,
        });
      }

      // 2) Create authority key bound to existing principal
      const { data: ak, error: akErr } = await supabase
        .from("solace_authority_keys")
        .insert({
          organization_id: org.id,
          principal_id: adminPrincipalId,
          public_key: reg.requested_public_key,
          key_purpose: "execution",
          valid_from: new Date().toISOString(),
          status: "active",
        })
        .select("id")
        .single();

      if (akErr || !ak) {
        return res.status(500).json({
          status: "error",
          reason: "authority_key_create_failed",
          detail: akErr?.message || null,
          requestId: (req as any).solaceRequestId,
        });
      }

      // 3) Generate API key and store hash only
      const rawApiKey = crypto.randomBytes(32).toString("base64url");
      const keyHash = crypto
        .createHash("sha256")
        .update(rawApiKey, "utf8")
        .digest("hex");

      const { data: apiKeyRow, error: apiErr } = await supabase
        .from("solace_api_keys")
        .insert({
          organization_id: org.id,
          key_hash: keyHash,
          status: "active",
        })
        .select("id")
        .single();

      if (apiErr || !apiKeyRow) {
        return res.status(500).json({
          status: "error",
          reason: "api_key_create_failed",
          detail: apiErr?.message || null,
          requestId: (req as any).solaceRequestId,
        });
      }

      // 4) Mark registration approved
      const reviewedBy = String(req.body?.reviewed_by || "").trim() || "admin";

      const { error: updErr } = await supabase
        .from("solace_client_registrations")
        .update({
          status: "approved",
          reviewed_by: reviewedBy,
          reviewed_at: new Date().toISOString(),
        })
        .eq("id", registrationId);

      if (updErr) {
        return res.status(500).json({
          status: "error",
          reason: "registration_update_failed",
          detail: updErr.message,
          requestId: (req as any).solaceRequestId,
        });
      }

      // Return raw key ONCE
      return res.status(200).json({
        status: "approved",
        registration_id: registrationId,
        organization_id: org.id,
        authority_key_id: ak.id,
        api_key_id: apiKeyRow.id,
        api_key: rawApiKey,
        requestId: (req as any).solaceRequestId,
      });
    } catch (e) {
      return res.status(500).json({
        status: "error",
        reason: asMessage(e),
        requestId: (req as any).solaceRequestId,
      });
    }
  }
);

/**
 * ------------------------------------------------------------
 * Tenant authentication middleware
 * ------------------------------------------------------------
 */
async function requireTenant(req: Request, res: Response, next: NextFunction) {
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
  windowMs: Number(process.env.SOLACE_RATE_LIMIT_WINDOW_SECONDS || 60) * 1000,
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
 *
 * IMPORTANT:
 * solace-core-authority currently exposes /v1/execute (NOT /v1/authorize).
 * So this endpoint proxies to Core /v1/execute and returns the Core decision,
 * without forwarding to any executor.
 *
 * Client should POST the SAME envelope shape used for /v1/gate:
 * { intent: {...}, execute: {...}, acceptance: {...} }
 * ------------------------------------------------------------
 */
app.post(
  "/v1/authorize",
  requireTenant,
  tenantRateLimiter,
  express.json({ limit: "256kb" }),
  async (req: Request, res: Response) => {
    try {
      // Keep backward-compat import (authorizeOnly) but do the correct Core call:
      const core = new SolaceCoreClient(cfg.core);
      const coreRes = await core.execute(req.body);

      return res.status(200).json({
        ...coreRes,
        requestId: (req as any).solaceRequestId,
      });

      // NOTE: If you later add /v1/authorize to Core, you can switch back to:
      // const result = await authorizeOnly(cfg, req.body);
      // return res.status(200).json({ ...result, requestId: (req as any).solaceRequestId });
    } catch (e) {
      return res.status(500).json({
        decision: "DENY",
        reason: asMessage(e),
        requestId: (req as any).solaceRequestId,
      });
    }
  }
);

export default app;
