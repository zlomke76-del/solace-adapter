// supabase/functions/executor-generic/index.ts
// Executor example: ONLY accepts adapter-forwarded requests.
// Hard locks:
//  1) x-solace-internal-secret header must match
//  2) receipt must verify (signature + TTL)
//  3) receipt.service must match THIS executor's service
//  4) executeHash must match payload

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { computeExecuteHash } from "../_shared/canonical.ts";
import { verifyReceiptV1, type ReceiptV1 } from "../_shared/receipt.ts";

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

type Incoming = {
  envelope: {
    intent: { actor: { id: string }; intent: string; [k: string]: unknown };
    execute: { action?: string; [k: string]: unknown };
    acceptance: { [k: string]: unknown };
  };
  receipt: ReceiptV1;
};

serve(async (req) => {
  if (req.method === "GET") {
    return json({ status: "ok", service: "executor-generic", time: new Date().toISOString() });
  }
  if (req.method !== "POST") return json({ decision: "DENY", reason: "method_not_allowed" }, 405);

  // Lock #1: internal secret header
  const expectedSecret = mustEnv("SOLACE_EXECUTOR_INTERNAL_SECRET");
  const got = req.headers.get("x-solace-internal-secret");
  if (!got || got !== expectedSecret) {
    return json({ decision: "DENY", reason: "missing_or_invalid_internal_secret" }, 403);
  }

  let body: Incoming | null = null;
  try {
    body = await req.json();
  } catch {
    return json({ decision: "DENY", reason: "invalid_json" }, 400);
  }

  if (!body?.envelope?.execute || !body?.receipt) {
    return json({ decision: "DENY", reason: "invalid_or_missing_executor_request" });
  }

  // Lock #2: receipt verify
  const receiptPublicKeyPem = mustEnv("SOLACE_ADAPTER_RECEIPT_PUBLIC_KEY_PEM");
  const expectedService = mustEnv("SOLACE_EXECUTOR_SERVICE"); // e.g. "payments" / "email" / "crm"

  const vr = await verifyReceiptV1({
    receipt: body.receipt,
    receiptPublicKeyPem,
    clockSkewSeconds: Number(Deno.env.get("SOLACE_CLOCK_SKEW_SECONDS") || "10") || 10,
  });

  if (!vr.ok) return json({ decision: "DENY", reason: vr.reason || "invalid_receipt" });

  // Lock #3: service match
  if (body.receipt.service !== expectedService) {
    return json({ decision: "DENY", reason: "receipt_service_mismatch" });
  }

  // Lock #4: executeHash match
  const localExecuteHash = await computeExecuteHash(body.envelope.execute);
  if (localExecuteHash !== body.receipt.executeHash) {
    return json({ decision: "DENY", reason: "execute_hash_mismatch" });
  }

  // ------------------------------------------------------------
  // SIDE EFFECTS GO HERE
  // ------------------------------------------------------------
  // This is where you call external APIs / send emails / write to CRM / etc.
  // If you do DB writes, do it with Supabase service role via env var
  // OR use RLS-safe anon flows depending on your model.
  //
  // IMPORTANT: never execute anything without passing the checks above.
  // ------------------------------------------------------------

  return json({
    decision: "PERMIT",
    reason: "executor_performed_side_effects",
    actorId: body.receipt.actorId,
    intent: body.receipt.intent,
    executeHash: body.receipt.executeHash,
    service: expectedService,
  });
});
