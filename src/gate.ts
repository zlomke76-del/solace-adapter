import { AdapterConfig, ExecuteEnvelope } from "./types.js";
import { callCoreExecute } from "./coreClient.js";
import { FailClosedError } from "./errors.js";

/**
 * gateExecution()
 * The adapter's invariant: side effects are blocked unless Core returns PERMIT.
 */
export async function gateExecution(cfg: AdapterConfig, envelope: ExecuteEnvelope) {
  if (!cfg.coreBaseUrl) throw new FailClosedError("coreBaseUrl_missing");

  // Always fail closed unless explicit PERMIT
  const resp = await callCoreExecute(cfg, envelope);

  if (resp.decision !== "PERMIT") {
    return {
      allowed: false as const,
      decision: resp.decision,
      reason: (resp as any).reason || "not_permitted",
      core: resp
    };
  }

  return {
    allowed: true as const,
    decision: "PERMIT" as const,
    core: resp
  };
}
