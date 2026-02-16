// src/executorVerifier.ts
// Drop-in verification helpers for ANY executor service.
// This is what makes the adapter non-bypassable.
// Executors MUST reject if receipt is missing/invalid.
//
// Expected request:
//   headers["x-solace-receipt"] = base64(JSON receipt)
//   body = { intent, execute }
//
// Executor must:
//   - decode + verify receipt signature
//   - enforce receipt window (short TTL)
//   - recompute executeHash and compare receipt.executeHash
//   - enforce intended service binding (receipt.service)
//   - enforce idempotency (receiptId or executeHash) on their side

import { computeExecuteHash } from "./canonical.js";
import { verifyReceipt } from "./receipt.js";
import type { Receipt } from "./types.js";

export function decodeReceiptHeader(headerValue: string | undefined): Receipt | null {
  if (!headerValue) return null;
  try {
    const json = Buffer.from(headerValue, "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

export function verifyExecutorRequest(params: {
  receiptHeader?: string;
  receiptPublicKeyPem: string;
  expectedService: string;
  execute: unknown;
  now?: Date;
  clockSkewSeconds?: number;
}): { ok: boolean; reason?: string; receipt?: Receipt; executeHash?: string } {
  const { receiptHeader, receiptPublicKeyPem, expectedService, execute } = params;

  const receipt = decodeReceiptHeader(receiptHeader);
  if (!receipt) return { ok: false, reason: "missing_or_invalid_receipt_header" };

  if (receipt.service !== expectedService) return { ok: false, reason: "receipt_service_mismatch" };

  const v = verifyReceipt({
    receipt,
    receiptPublicKeyPem,
    now: params.now,
    clockSkewSeconds: params.clockSkewSeconds ?? 10,
  });
  if (!v.ok) return { ok: false, reason: v.reason || "invalid_receipt" };

  const executeHash = computeExecuteHash(execute);
  if (executeHash !== receipt.executeHash) return { ok: false, reason: "execute_hash_mismatch" };

  return { ok: true, receipt, executeHash };
}
