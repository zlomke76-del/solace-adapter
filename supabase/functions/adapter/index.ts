// supabase/functions/adapter/index.ts
// Public entrypoint. This is the ONLY public path to side effects.
// Flow: validate -> call Core /v1/execute -> mint adapter receipt -> forward to executor
//
// HARD RULE: no forwarding unless Core returns PERMIT.

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { computeExecuteHash, computeIntentHash } from "../_shared/canonical.ts";
import { signReceiptV1 } from "../_shared/receipt.ts";

type GateEnvelope = {
  intent: { actor: { id: string }; intent: string; [k: string]: unknown };
  execute: { action?: string; [k: string]: unknown };
  acceptance: { [k: string]: unknown };
};

function json(resBody: unknown, status = 200) {
  return new Response(JSON.stringify(resBody), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function mustEnv(name: string): string {
  const v = Deno.env.get(name);
  if (!v || !v.trim()) throw new Error(`missing_env_${name}`);
  return v;
}

function optEnv(name: string): string | null {
  const v = Deno.env.get(name);
  return v && v.trim() ? v : null;
}

function safeParseJson(text: string): any {
  try { return JSON.parse(text); } catch { return { _raw: text }; }
}

function baseUrlJoin(base: string, path: string): string {
  const b = base.replace(/\/+$/, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${b}${p}`;
}

function normalizeHeaders(extraJson: string | null): Record<string, string> {
  if (!extraJson) return {};
  const parsed = safeParseJson(extraJson);
  if (!parsed || typeof parsed !== "object") return {};
  const out: Record<string, string> = {};
  for (const k of Object.keys(parsed)) {
    const v = (parsed as any)[k];
    if (typeof v === "string") out[k] = v;
  }
  return out;
}

// Routing table: action -> executor function URL
// In Supabase: https://<project-ref>.functions.supabase.co/<function-name>
type Targets = Record<string, { url: string }>;

function loadTargets(): { actionToService: Record<string, string>; targets: Targets } {
  const actionToServiceRaw = mustEnv("SOLACE_ADAPTER_ACTION_TO_SERVICE_JSON");
  const targetsRaw = mustEnv("SOLACE_ADAPTER_TARGETS_JSON");

  const actionToService = safeParseJson(actionToServiceRaw);
  const targets = safeParseJson(targetsRaw);

  if (!actionToService || typeof actionToService !== "object") throw new Error("invalid_actionToService_json");
  if (!targets || typeof targets !== "object") throw new Error("invalid_targets_json");

  return { actionToService, targets };
}

serve(async (req) => {
  if (req.method === "GET") {
    return json({ status: "ok", service: "solace-adapter", time: new Date().toISOString() });
  }

  if (req.method !== "POST") return json({ decision: "DENY", reason: "method_not_allowed" }, 405);

  let body: GateEnvelope | null = null;
  try {
    body = await req.json();
  } catch (e) {
    return json({ decision: "DENY", reason: "invalid_json", error: String(e?.message || e) }, 400);
  }

  // Minimal structural validation (fail-closed for execution)
  if (!body?.intent?.actor?.id || !body.intent.intent || !body.execute || !body.acceptance) {
    return json({ decision: "DENY", reason: "invalid_or_missing_gate_request" });
  }

  const actorId = String(body.intent.actor.id);
  const intentName = String(body.intent.intent);
  const action = String((body.execute as any).action || "");

  const { actionToService, targets } = loadTargets();
  const service = actionToService[action];
  if (!service) return json({ decision: "DENY", reason: "unknown_action_route" });

  const target = targets[service];
  if (!target?.url) return json({ decision: "DENY", reason: "unknown_forward_target" });

  const CORE_BASE = mustEnv("SOLACE_CORE_BASE_URL");
  const CORE_HEADERS_JSON = optEnv("SOLACE_CORE_HEADERS_JSON");
  const CORE_HEADERS = normalizeHeaders(CORE_HEADERS_JSON);

  const ADAPTER_ID = mustEnv("SOLACE_ADAPTER_ID");
  const RECEIPT_PRIVATE_KEY = mustEnv("SOLACE_ADAPTER_RECEIPT_PRIVATE_KEY_PEM");
  const RECEIPT_TTL_SECONDS = Number(optEnv("SOLACE_ADAPTER_RECEIPT_TTL_SECONDS") || "30") || 30;

  // Internal secret shared with executors (second lock)
  const INTERNAL_SECRET = mustEnv("SOLACE_EXECUTOR_INTERNAL_SECRET");

  // 1) Call Core /v1/execute
  const coreUrl = baseUrlJoin(CORE_BASE, "/v1/execute");

  let coreRes: any = null;
  try {
    const r = await fetch(coreUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...CORE_HEADERS,
      },
      body: JSON.stringify(body),
    });

    // Adapter fail-closed: if core is unhealthy/unreachable -> DENY
    if (!r.ok) return json({ decision: "DENY", reason: `core_http_${r.status}` });

    coreRes = safeParseJson(await r.text());
    if (!coreRes || typeof coreRes.decision !== "string") {
      return json({ decision: "DENY", reason: "core_malformed_response" });
    }
  } catch {
    return json({ decision: "DENY", reason: "core_unreachable" });
  }

  if (coreRes.decision !== "PERMIT") {
    // No forwarding unless PERMIT
    return json({ decision: coreRes.decision, reason: coreRes.reason || "core_denied" });
  }

  // 2) Compute hashes (prefer Core output, but compute locally too)
  const localExecuteHash = await computeExecuteHash(body.execute);
  const localIntentHash = await computeIntentHash(body.intent);

  const executeHash = typeof coreRes.executeHash === "string" ? coreRes.executeHash : localExecuteHash;
  const intentHash = typeof coreRes.intentHash === "string" ? coreRes.intentHash : localIntentHash;

  // 3) Mint adapter receipt for executor
  const receipt = await signReceiptV1({
    adapterId: ADAPTER_ID,
    service,
    actorId,
    intent: intentName,
    intentHash,
    executeHash,
    authorityKeyId: coreRes.authorityKeyId ?? null,
    coreIssuedAt: coreRes.issuedAt,
    coreExpiresAt: coreRes.expiresAt,
    coreTime: coreRes.time,
    receiptPrivateKeyPem: RECEIPT_PRIVATE_KEY,
    ttlSeconds: RECEIPT_TTL_SECONDS,
  });

  // 4) Forward to executor (with internal secret header)
  try {
    const fr = await fetch(target.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-solace-internal-secret": INTERNAL_SECRET,
      },
      body: JSON.stringify({
        envelope: body,
        receipt,
      }),
    });

    const ftext = await fr.text();
    const fbody = ftext ? safeParseJson(ftext) : null;

    return json({
      decision: "PERMIT",
      reason: "forwarded_after_core_permit",
      service,
      forwardStatus: fr.status,
      forwardBody: fbody,
      executeHash,
      intentHash,
      authorityKeyId: coreRes.authorityKeyId ?? null,
      receipt,
    });
  } catch (e) {
    // Adapter did not execute side effects itself; forwarding failed.
    return json({
      decision: "DENY",
      reason: "forwarding_failed",
      error: String(e?.message || e),
    });
  }
});
