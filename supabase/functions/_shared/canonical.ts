// supabase/functions/_shared/canonical.ts
// Deterministic canonicalization + SHA256 (ASCII-safe).

export function stableSort(value: unknown): unknown {
  if (value === null || value === undefined) return value;

  if (Array.isArray(value)) return value.map(stableSort);

  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(obj).sort()) {
      out[k] = stableSort(obj[k]);
    }
    return out;
  }

  return value;
}

export function canonicalize(obj: unknown): string {
  return JSON.stringify(stableSort(obj));
}

export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  const arr = Array.from(new Uint8Array(hash));
  return arr.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function computeExecuteHash(execute: unknown): Promise<string> {
  return sha256Hex(canonicalize(execute));
}

export async function computeIntentHash(intent: unknown): Promise<string> {
  return sha256Hex(canonicalize(intent));
}
