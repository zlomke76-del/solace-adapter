import crypto from "crypto";

function stableSort(value: any): any {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(stableSort);
  if (typeof value === "object") {
    const out: Record<string, any> = {};
    for (const k of Object.keys(value).sort()) out[k] = stableSort(value[k]);
    return out;
  }
  return value;
}

export function canonical(obj: any): string {
  return JSON.stringify(stableSort(obj));
}

export function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(String(input)).digest("hex");
}

export function computeExecuteHash(execute: any): string {
  return sha256Hex(canonical(execute));
}

export function computeIntentHash(intent: any): string {
  return sha256Hex(canonical(intent));
}
