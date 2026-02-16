// src/gate.ts

import type {
  AdapterForwardingConfig,
  AdapterGateResult,
  GateRequestEnvelope,
} from "./types.js";
import { computeExecuteHash, computeIntentHash } from "./canonical.js";
import { SolaceCoreClient } from "./coreClient.js";
import { signReceipt } from "./receipt.js";
import { forwardToExecutor } from "./forwarding.js";
import { ConfigError } from "./errors.js";

function requireCfg(cfg: AdapterForwardingConfig) {
  if (!cfg) throw new ConfigError("missing_adapter_config");
  if (!cfg.adapterId) throw new ConfigError("missing_adapterId");
  if (!cfg.receiptPrivateKeyPem) throw new ConfigError("missing_receiptPrivateKeyPem");
  if (!cfg.receiptPublicKeyPem) throw new ConfigError("missing_receiptPublicKeyPem");
  if (!cfg.core?.coreBaseUrl) throw new ConfigError("missing_core_base_url");
  if (!cfg.actionToService) throw new ConfigError("missing_actionToService");
  if (!cfg.targets) throw new ConfigError("missing_targets");
}

export async function gateAndForward(
  cfg: AdapterForwardingConfig,
  envelope: GateRequestEnvelope
): Promise<AdapterGateResult> {
  requireCfg(cfg);

  // Minimal envelope validation (adapter is fail-closed for execution)
  if (!envelope?.intent?.actor?.id || !envelope.intent.intent || !envelope.execute || !envelope.acceptance) {
    return { decision: "DENY", reason: "invalid_or_missing_gate_request" };
  }

  const actorId = String(envelope.intent.actor.id);
  const intentName = String(envelope.intent.intent);

  // Route to execution service (this is what makes the adapter the control plane)
  const action = String((envelope.execute as any).action || "");
  const service = cfg.actionToService[action];
  if (!service) return { decision: "DENY", reason: "unknown_action_route" };
  if (!cfg.targets[service]) return { decision: "DENY", reason: "unknown_forward_target" };

  // Call Core /v1/execute (this is the authoritative permit)
  const core = new SolaceCoreClient(cfg.core);
  const coreRes = await core.execute(envelope);

  if (coreRes.decision !== "PERMIT") {
    // Adapter must fail closed: no forwarding.
    return {
      decision: coreRes.decision,
      reason: coreRes.reason || "core_denied",
    };
  }

  // Compute hashes (prefer Core output, but recompute to be consistent at adapter layer)
  const localExecuteHash = computeExecuteHash(envelope.execute);
  const localIntentHash = computeIntentHash(envelope.intent);

  const executeHash = coreRes.executeHash || localExecuteHash;
  const intentHash = coreRes.intentHash || localIntentHash;

  // Mint short-lived receipt for executor to verify.
  const receiptTtlSeconds = cfg.receiptTtlSeconds ?? 30;

  const receipt = signReceipt({
    adapterId: cfg.adapterId,
    service,
    actorId,
    intent: intentName,
    executeHash,
    intentHash,
    authorityKeyId: coreRes.authorityKeyId ?? null,
    coreIssuedAt: coreRes.issuedAt,
    coreExpiresAt: coreRes.expiresAt,
    coreTime: coreRes.time,
    receiptPrivateKeyPem: cfg.receiptPrivateKeyPem,
    receiptTtlSeconds,
  });

  // Forward to executor (only after PERMIT)
  const forwarded = await forwardToExecutor({ cfg, service, envelope, receipt });

  return {
    decision: "PERMIT",
    reason: "forwarded_after_core_permit",
    receipt,
    forwardStatus: forwarded.status,
    forwardBody: forwarded.body,
    executeHash,
    intentHash,
    authorityKeyId: coreRes.authorityKeyId ?? null,
  };
}

export async function authorizeOnly(cfg: AdapterForwardingConfig, intentObj: unknown) {
  requireCfg(cfg);
  const core = new SolaceCoreClient(cfg.core);
  return core.authorize(intentObj);
}
