import { AdapterConfig, CoreExecuteResponse, ExecuteEnvelope } from "./types.js";
import { FailClosedError } from "./errors.js";

function withTimeout(ms: number): AbortController {
  const ac = new AbortController();
  setTimeout(() => ac.abort(), ms).unref?.();
  return ac;
}

export async function callCoreExecute(
  cfg: AdapterConfig,
  body: ExecuteEnvelope
): Promise<CoreExecuteResponse> {
  const base = cfg.coreBaseUrl.replace(/\/+$/, "");
  const path = (cfg.coreExecutePath || "/v1/execute").startsWith("/")
    ? (cfg.coreExecutePath || "/v1/execute")
    : `/${cfg.coreExecutePath || "v1/execute"}`;

  const url = `${base}${path}`;
  const timeoutMs = cfg.timeoutMs ?? 4000;
  const ac = withTimeout(timeoutMs);

  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ac.signal
    });
  } catch (e: any) {
    // FAIL CLOSED on network / timeout / DNS, etc.
    throw new FailClosedError(String(e?.message || "core_unreachable"));
  }

  // FAIL CLOSED on non-2xx per contract
  if (!resp.ok) {
    throw new FailClosedError(`core_http_${resp.status}`);
  }

  let json: any;
  try {
    json = await resp.json();
  } catch {
    throw new FailClosedError("core_malformed_json");
  }

  // FAIL CLOSED on malformed decision
  if (!json || typeof json.decision !== "string") {
    throw new FailClosedError("core_malformed_response");
  }

  return json as CoreExecuteResponse;
}
