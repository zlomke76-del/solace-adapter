// src/config.ts

import fs from "fs";
import type { AdapterForwardingConfig, CoreClientConfig, ForwardTarget } from "./types";
import { ConfigError } from "./errors";

function readFileIfExists(p: string): string | null {
  try {
    if (!p) return null;
    if (!fs.existsSync(p)) return null;
    return fs.readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

function mustEnv(name: string): string {
  const v = process.env[name];
  if (!v || !String(v).trim()) throw new ConfigError(`missing_env_${name}`);
  return String(v);
}

function optEnv(name: string): string | undefined {
  const v = process.env[name];
  if (!v || !String(v).trim()) return undefined;
  return String(v);
}

function parseJson<T>(raw: string, name: string): T {
  try {
    return JSON.parse(raw) as T;
  } catch (e) {
    throw new ConfigError(`invalid_json_${name}`, { rawPreview: raw.slice(0, 200) });
  }
}

function parseIntOpt(v: string | undefined, def: number): number {
  if (!v) return def;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : def;
}

function loadPem(params: { pemEnv?: string; pathEnv?: string; label: string }): string {
  const pemFromEnv = params.pemEnv ? optEnv(params.pemEnv) : undefined;
  if (pemFromEnv && pemFromEnv.includes("BEGIN")) return pemFromEnv;

  const p = params.pathEnv ? optEnv(params.pathEnv) : undefined;
  if (p) {
    const txt = readFileIfExists(p);
    if (txt && txt.includes("BEGIN")) return txt;
  }

  throw new ConfigError(`missing_${params.label}_pem`, {
    expected: params.pemEnv ? [params.pemEnv, params.pathEnv].filter(Boolean) : [params.pathEnv].filter(Boolean),
  });
}

type TargetsJson = Record<
  string,
  {
    url: string;
    bearerToken?: string;
  }
>;

export function loadAdapterConfigFromEnv(): AdapterForwardingConfig {
  const adapterId = mustEnv("SOLACE_ADAPTER_ID");
  const coreBaseUrl = mustEnv("SOLACE_CORE_BASE_URL");

  const receiptPrivateKeyPem = loadPem({
    pemEnv: "SOLACE_ADAPTER_RECEIPT_PRIVATE_KEY_PEM",
    pathEnv: "SOLACE_ADAPTER_RECEIPT_PRIVATE_KEY_PATH",
    label: "receipt_private_key",
  });

  const receiptPublicKeyPem = loadPem({
    pemEnv: "SOLACE_ADAPTER_RECEIPT_PUBLIC_KEY_PEM",
    pathEnv: "SOLACE_ADAPTER_RECEIPT_PUBLIC_KEY_PATH",
    label: "receipt_public_key",
  });

  const receiptTtlSeconds = parseIntOpt(optEnv("SOLACE_ADAPTER_RECEIPT_TTL_SECONDS"), 30);
  const clockSkewSeconds = parseIntOpt(optEnv("SOLACE_ADAPTER_CLOCK_SKEW_SECONDS"), 10);

  const timeoutMs = parseIntOpt(optEnv("SOLACE_CORE_TIMEOUT_MS"), 8000);

  const coreHeadersJson = optEnv("SOLACE_CORE_HEADERS_JSON");
  const headers = coreHeadersJson ? parseJson<Record<string, string>>(coreHeadersJson, "SOLACE_CORE_HEADERS_JSON") : {};

  const core: CoreClientConfig = {
    coreBaseUrl,
    timeoutMs,
    headers,
  };

  const actionToServiceJson = mustEnv("SOLACE_ADAPTER_ACTION_TO_SERVICE_JSON");
  const actionToService = parseJson<Record<string, string>>(actionToServiceJson, "SOLACE_ADAPTER_ACTION_TO_SERVICE_JSON");

  const targetsJsonRaw = mustEnv("SOLACE_ADAPTER_TARGETS_JSON");
  const targetsJson = parseJson<TargetsJson>(targetsJsonRaw, "SOLACE_ADAPTER_TARGETS_JSON");

  const targets: Record<string, ForwardTarget> = {};
  for (const service of Object.keys(targetsJson)) {
    const t = targetsJson[service];
    if (!t?.url) throw new ConfigError("invalid_target_missing_url", { service });
    targets[service] = {
      service,
      url: String(t.url),
      bearerToken: t.bearerToken ? String(t.bearerToken) : undefined,
    };
  }

  return {
    adapterId,
    receiptPrivateKeyPem,
    receiptPublicKeyPem,
    receiptTtlSeconds,
    clockSkewSeconds,
    core,
    actionToService,
    targets,
  };
}
