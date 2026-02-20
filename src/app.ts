import express, { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { createRequire } from "module";
import { createClient } from "@supabase/supabase-js";
import { loadAdapterConfigFromEnv } from "./config.js";
import { gateAndForward } from "./gate.js";
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
 * Public Registration Endpoint
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

      if (!public_key.includes("BEGIN PUBLIC KEY")) {
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
 * Admin Approval Endpoint
 * ------------------------------------------------------------
 */
app.post(
  "/v1/admin/approve",
  express.json(),
  async (req: Request, res: Response) => {
    const adminToken = process.env.SOLACE_ADMIN_TOKEN;
    const provided =
      String(req.header("authorization") || "").replace("Bearer ", "");

    if (!adminToken || provided !== adminToken) {
      return res.status(401).json({
        status: "error",
        reason: "unauthorized",
        requestId: (req as any).solaceRequestId,
      });
    }

    try {
      const { registration_id, reviewed_by } = req.body || {};

      if (!registration_id) {
        return res.status(400).json({
          status: "error",
          reason: "missing_registration_id",
        });
      }

      // Fetch registration
      const { data: reg, error: regErr } = await supabase
        .from("solace_client_registrations")
        .select("*")
        .eq("id", registration_id)
        .single();

      if (regErr || !reg) {
        return res.status(404).json({
          status: "error",
          reason: "registration_not_found",
        });
      }

      // Create organization
      const { data: org } = await supabase
        .from("solace_organizations")
        .insert({
          legal_name: reg.legal_name,
          legal_entity_type: reg.legal_entity_type,
          jurisdiction: reg.jurisdiction,
        })
        .select("id")
        .single();

      // Create authority key
      const { data: authKey } = await supabase
        .from("solace_authority_keys")
        .insert({
          organization_id: org.id,
          principal_id: process.env.SOLACE_ADMIN_PRINCIPAL_ID,
          public_key: reg.requested_public_key,
          key_purpose: "external_client",
          valid_from: new Date().toISOString(),
        })
        .select("id")
        .single();

      // Generate API key
      const apiKey = crypto.randomBytes(32).toString("base64url");
      const keyHash = crypto
        .createHash("sha256")
        .update(apiKey)
        .digest("hex");

      const { data: apiKeyRow } = await supabase
        .from("solace_api_keys")
        .insert({
          organization_id: org.id,
          key_hash: keyHash,
        })
        .select("id")
        .single();

      // Mark registration approved
      await supabase
        .from("solace_client_registrations")
        .update({
          status: "approved",
          reviewed_by: reviewed_by || "admin",
          reviewed_at: new Date().toISOString(),
        })
        .eq("id", registration_id);

      return res.json({
        status: "approved",
        registration_id,
        organization_id: org.id,
        authority_key_id: authKey.id,
        api_key_id: apiKeyRow.id,
        api_key: apiKey,
        requestId: (req as any).solaceRequestId,
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

  const keyHash = crypto
    .createHash("sha256")
    .update(apiKeyRaw.trim())
    .digest("hex");

  const { data } = await supabase
    .from("solace_api_keys")
    .select("id, status")
    .eq("organization_id", orgId)
    .eq("key_hash", keyHash)
    .maybeSingle();

  if (!data || data.status !== "active") {
    return res.status(403).json({
      decision: "DENY",
      reason: "invalid_or_revoked_api_key",
      requestId: (req as any).solaceRequestId,
    });
  }

  (req as any).solaceTenant = { organizationId: orgId };
  next();
}

/**
 * ------------------------------------------------------------
 * Gate Endpoint (Core authoritative decision)
 * ------------------------------------------------------------
 */
app.post(
  "/v1/gate",
  requireTenant,
  express.json({ limit: "512kb" }),
  async (req: Request, res: Response) => {
    try {
      const result = await gateAndForward(cfg, req.body);

      return res.status(
        result.decision === "PERMIT" ? 200 : 403
      ).json({
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

export default app;
