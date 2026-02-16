// src/receipt.ts

import crypto from "crypto";
import { canonicalize, sha256Hex } from "./canonical.js";
import type { Receipt } from "./types.js";
import { ConfigError } from "./errors.js";

// NOTE: We use Ed25519 receipts by default (simple + robust). PEM is required.
// crypto.sign(null, data, privateKey) works for Ed25519 in Node.
function signEd25519Base64(privateKeyPem: string, material: string): string {
  const sig = crypto.sign(null, Buffer.from(material, "utf8"), privateKeyPem);
  return sig.toString("base64");
}

function verifyEd25519Base64(publicKeyPem: string, material: string, signatureB64: string): boolean {
  return crypto.verify(null, Buffer.from(material, "utf8"), publicKeyPem, Buffer.from(signatureB64, "base64"));
}

function uuidV4(): string {
  // Node 19+ has crypto.randomUUID; keep compatible with Node 18+
  return crypto.randomUUID ? crypto.randomUUID() : ([1e7] as any + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, (c: any) =>
    (c ^ (crypto.randomBytes(1)[0] & (15 >> (c / 4)))).toString(16)
  );
}

function toIso(d: Date): string {
  return d.toISOString();
}

export function buildReceiptUnsigned(input: Omit<Receipt, "signature">): Omit<Receipt, "signature"> {
  return input;
}

export function receiptSigningMaterial(unsigned: Omit<Receipt, "signature">): string {
  // Signature never includes itself
  return canonicalize(unsigned);
}

export function signReceipt(params: {
  adapterId: string;
  service: string;

  actorId: string;
  intent: string;
  executeHash: string;

  intentHash: string;
  authorityKeyId?: string | null;

  coreIssuedAt?: string;
  coreExpiresAt?: string;
  coreTime?: string;

  receiptPrivateKeyPem: string;
  receiptTtlSeconds: number;
}): Receipt {
  const {
    adapterId,
    service,
    actorId,
    intent,
    executeHash,
    intentHash,
    authorityKeyId,
    coreIssuedAt,
    coreExpiresAt,
    coreTime,
    receiptPrivateKeyPem,
    receiptTtlSeconds,
  } = params;

  if (!receiptPrivateKeyPem) throw new ConfigError("missing_receipt_private_key_pem");
  if (!adapterId) throw new ConfigError("missing_adapterId");
  if (!service) throw new ConfigError("missing_service");

  const now = new Date();
  const exp = new Date(now.getTime() + receiptTtlSeconds * 1000);

  const unsigned: Omit<Receipt, "signature"> = {
    v: 1,
    receiptId: uuidV4(),
    adapterId,
    service,

    actorId,
    intent,
    executeHash,

    intentHash,
    coreDecision: "PERMIT",
    coreIssuedAt,
    coreExpiresAt,
    coreTime,
    authorityKeyId: authorityKeyId ?? null,

    issuedAt: toIso(now),
    expiresAt: toIso(exp),
  };

  const material = receiptSigningMaterial(unsigned);
  const signature = signEd25519Base64(receiptPrivateKeyPem, material);

  return { ...unsigned, signature };
}

export function verifyReceipt(params: {
  receipt: Receipt;
  receiptPublicKeyPem: string;
  now?: Date;
  clockSkewSeconds?: number;
}): { ok: boolean; reason?: string } {
  const { receipt, receiptPublicKeyPem } = params;
  const now = params.now ?? new Date();
  const skew = params.clockSkewSeconds ?? 10;

  if (!receiptPublicKeyPem) return { ok: false, reason: "missing_receipt_public_key" };
  if (!receipt || receipt.v !== 1) return { ok: false, reason: "invalid_receipt_version" };
  if (receipt.coreDecision !== "PERMIT") return { ok: false, reason: "receipt_not_permit" };
  if (!receipt.signature) return { ok: false, reason: "missing_receipt_signature" };

  const issuedAt = new Date(receipt.issuedAt);
  const expiresAt = new Date(receipt.expiresAt);
  if (Number.isNaN(issuedAt.getTime()) || Number.isNaN(expiresAt.getTime())) {
    return { ok: false, reason: "invalid_receipt_time_fields" };
  }

  // allow small skew
  const issuedOk = now.getTime() + skew * 1000 >= issuedAt.getTime();
  const notExpired = now.getTime() - skew * 1000 <= expiresAt.getTime();
  if (!issuedOk) return { ok: false, reason: "receipt_not_yet_valid" };
  if (!notExpired) return { ok: false, reason: "receipt_expired" };

  const { signature, ...unsigned } = receipt;
  const material = receiptSigningMaterial(unsigned as any);

  const sigOk = verifyEd25519Base64(receiptPublicKeyPem, material, signature);
  if (!sigOk) return { ok: false, reason: "invalid_receipt_signature" };

  return { ok: true };
}

export function receiptHash(receipt: Receipt): string {
  return sha256Hex(canonicalize(receipt));
}
