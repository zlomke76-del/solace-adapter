// supabase/functions/_shared/receipt.ts
// Adapter receipts using Ed25519 (WebCrypto).
// Receipt binds service + executeHash (+ intentHash for audit usefulness).

import { canonicalize } from "./canonical.ts";

export type ReceiptV1 = {
  v: 1;
  adapterId: string;
  service: string;
  actorId: string;
  intent: string;
  intentHash: string;
  executeHash: string;
  authorityKeyId?: string | null;

  coreIssuedAt?: string;
  coreExpiresAt?: string;
  coreTime?: string;

  issuedAt: string;
  expiresAt: string;

  signature: string; // base64
};

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

async function importEd25519PrivateKeyPem(pem: string): Promise<CryptoKey> {
  // Expect PKCS8 PEM for Ed25519
  const clean = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const keyBytes = b64ToBytes(clean);

  return crypto.subtle.importKey(
    "pkcs8",
    keyBytes,
    { name: "Ed25519" } as any,
    false,
    ["sign"]
  );
}

async function importEd25519PublicKeyPem(pem: string): Promise<CryptoKey> {
  // Expect SPKI PEM for Ed25519
  const clean = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  const keyBytes = b64ToBytes(clean);

  return crypto.subtle.importKey(
    "spki",
    keyBytes,
    { name: "Ed25519" } as any,
    false,
    ["verify"]
  );
}

export function receiptSigningMaterial(unsigned: Omit<ReceiptV1, "signature">): string {
  return canonicalize(unsigned);
}

export async function signReceiptV1(params: {
  adapterId: string;
  service: string;
  actorId: string;
  intent: string;
  intentHash: string;
  executeHash: string;
  authorityKeyId?: string | null;

  coreIssuedAt?: string;
  coreExpiresAt?: string;
  coreTime?: string;

  receiptPrivateKeyPem: string;
  ttlSeconds: number;
}): Promise<ReceiptV1> {
  const now = new Date();
  const exp = new Date(now.getTime() + params.ttlSeconds * 1000);

  const unsigned: Omit<ReceiptV1, "signature"> = {
    v: 1,
    adapterId: params.adapterId,
    service: params.service,
    actorId: params.actorId,
    intent: params.intent,
    intentHash: params.intentHash,
    executeHash: params.executeHash,
    authorityKeyId: params.authorityKeyId ?? null,

    coreIssuedAt: params.coreIssuedAt,
    coreExpiresAt: params.coreExpiresAt,
    coreTime: params.coreTime,

    issuedAt: now.toISOString(),
    expiresAt: exp.toISOString(),
  };

  const material = receiptSigningMaterial(unsigned);
  const key = await importEd25519PrivateKeyPem(params.receiptPrivateKeyPem);
  const sig = await crypto.subtle.sign(
    { name: "Ed25519" } as any,
    key,
    new TextEncoder().encode(material)
  );

  const signature = bytesToB64(new Uint8Array(sig));
  return { ...unsigned, signature };
}

export async function verifyReceiptV1(params: {
  receipt: ReceiptV1;
  receiptPublicKeyPem: string;
  now?: Date;
  clockSkewSeconds?: number;
}): Promise<{ ok: boolean; reason?: string }> {
  const { receipt } = params;
  const now = params.now ?? new Date();
  const skew = params.clockSkewSeconds ?? 10;

  if (!receipt || receipt.v !== 1) return { ok: false, reason: "invalid_receipt_version" };
  if (!receipt.signature) return { ok: false, reason: "missing_receipt_signature" };

  const issuedAt = new Date(receipt.issuedAt);
  const expiresAt = new Date(receipt.expiresAt);
  if (Number.isNaN(issuedAt.getTime()) || Number.isNaN(expiresAt.getTime())) {
    return { ok: false, reason: "invalid_receipt_time_fields" };
  }

  const issuedOk = now.getTime() + skew * 1000 >= issuedAt.getTime();
  const notExpired = now.getTime() - skew * 1000 <= expiresAt.getTime();
  if (!issuedOk) return { ok: false, reason: "receipt_not_yet_valid" };
  if (!notExpired) return { ok: false, reason: "receipt_expired" };

  const { signature, ...unsigned } = receipt;
  const material = receiptSigningMaterial(unsigned as any);

  const pub = await importEd25519PublicKeyPem(params.receiptPublicKeyPem);
  const sigOk = await crypto.subtle.verify(
    { name: "Ed25519" } as any,
    pub,
    b64ToBytes(signature),
    new TextEncoder().encode(material)
  );

  if (!sigOk) return { ok: false, reason: "invalid_receipt_signature" };
  return { ok: true };
}
