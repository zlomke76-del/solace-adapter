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
  if (!cfg.targets) throw new ConfigError("missing_targets");
}

export async function gateAndForward(
  cfg: AdapterForwardingConfig,
  envelope: GateRequestEnvelope
): Promise<AdapterGateResult> {
  requireCfg(cfg);

  // Minimal envelope validation (adapter is fail-closed for execution)
  if (
    !envelope?.intent?.actor?.id ||
    !envelope.intent.intent ||
    !envelope.execute ||
    !envelope.acceptance
  ) {
    return { decision: "DENY", reason: "invalid_or_missing_gate_request" };
  }

  const actorId = String(envelope.intent.actor.id);
  const intentName = String(envelope.intent.intent);

  /**
   * ------------------------------------------------------------
   * PREFIX ROUTING (service:operation)
   * ------------------------------------------------------------
   * execute.action must be formatted as:
   *   "<service>:<operation>"
   *
   * Example:
   *   "payments:refund"
   *   "booking:cancel"
   *
   * Adapter enforces:
   * - valid format
   * - declared service exists in cfg.targets
   * - fail-closed otherwise
   * ------------------------------------------------------------
   */

  const rawAction = String((envelope.execute as any).action || "").trim();

  if (!rawAction.includes(":")) {
    return { decision: "DENY", reason: "invalid_action_format" };
  }

  const [service, operation] = rawAction.split(":", 2);

  if (!service || !operation) {
    return { decision: "DENY", reason: "invalid_action_format" };
  }

  if (!cfg.targets[service]) {
    return { decision: "DENY", reason: "unknown_forward_target" };
  }

  /**
   * ------------------------------------------------------------
   * Call Core /v1/execute (authoritative decision)
   * ------------------------------------------------------------
   */
  const core = new SolaceCoreClient(cfg.core);
  const coreRes = await core.execute(envelope);

  if (coreRes.decision !== "PERMIT") {
    // Adapter must fail closed: no forwarding.
    return {
      decision: coreRes.decision,
      reason: coreRes.reason || "core_denied",
    };
  }

  /**
   * ------------------------------------------------------------
   * Hash binding
   * ------------------------------------------------------------
   */
  const localExecuteHash = computeExecuteHash(envelope.execute);
  const localIntentHash = computeIntentHash(envelope.intent);

  const executeHash = coreRes.executeHash || localExecuteHash;
  const intentHash = coreRes.intentHash || localIntentHash;

  /**
   * ------------------------------------------------------------
   * Mint short-lived cryptographic receipt
   * ------------------------------------------------------------
   */
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

  /**
   * ------------------------------------------------------------
   * Forward to executor (only after PERMIT)
   * ------------------------------------------------------------
   */
  const forwarded = await forwardToExecutor({
    cfg,
    service,
    envelope,
    receipt,
  });

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

export async function authorizeOnly(
  cfg: AdapterForwardingConfig,
  intentObj: unknown
) {
  requireCfg(cfg);
  const core = new SolaceCoreClient(cfg.core);
  return core.authorize(intentObj);
}
