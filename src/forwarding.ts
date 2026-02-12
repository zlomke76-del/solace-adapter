// src/forwarding.ts

import type { AdapterForwardingConfig, GateRequestEnvelope, Receipt } from "./types";
import { ForwardingError } from "./errors";

async function safeJson(res: Response): Promise<any> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { _raw: text };
  }
}

export function encodeReceiptHeader(receipt: Receipt): string {
  // Keep it simple: base64(JSON)
  const json = JSON.stringify(receipt);
  return Buffer.from(json, "utf8").toString("base64");
}

export async function forwardToExecutor(params: {
  cfg: AdapterForwardingConfig;
  service: string;
  envelope: GateRequestEnvelope;
  receipt: Receipt;
}): Promise<{ status: number; body: any }> {
  const { cfg, service, envelope, receipt } = params;

  const target = cfg.targets[service];
  if (!target) throw new ForwardingError("unknown_forward_target", { service });

  // IMPORTANT: in forwarding mode, the executor is allowed to accept ONLY:
  // - receipt header
  // - execute payload (and optionally the intent for logging), but NEVER the acceptance.
  // acceptance stays between (client -> adapter -> core). Executors should not trust it.

  const res = await fetch(target.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-solace-receipt": encodeReceiptHeader(receipt),
      ...(target.bearerToken ? { authorization: `Bearer ${target.bearerToken}` } : {}),
    },
    body: JSON.stringify({
      intent: envelope.intent,
      execute: envelope.execute,
      // DO NOT forward acceptance
    }),
  });

  const body = await safeJson(res);
  return { status: res.status, body };
}
