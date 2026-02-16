// src/canonical.ts

import crypto from "crypto";
import type { JsonValue } from "./types.js";

function stableSort(value: any): any {
  if (value === null || value === undefined) return value;

  if (Array.isArray(value)) return value.map(stableSort);

  if (typeof value === "object") {
    const out: any = {};
    for (const k of Object.keys(value).sort()) out[k] = stableSort(value[k]);
    return out;
  }

  return value;
}

export function canonicalize(value: JsonValue | unknown): string {
  return JSON.stringify(stableSort(value as any));
}

export function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(String(input)).digest("hex");
}

export function computeIntentHash(intent: unknown): string {
  return sha256Hex(canonicalize(intent));
}

export function computeExecuteHash(execute: unknown): string {
  return sha256Hex(canonicalize(execute));
}

export function computeAcceptanceHash(acceptance: unknown): string {
  return sha256Hex(canonicalize(acceptance));
}
