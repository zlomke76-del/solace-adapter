// api/v1/gate.ts

import type { VercelRequest, VercelResponse } from "@vercel/node";
import { gateAndForward } from "../../src/gate";
import { loadAdapterConfig } from "../../src/config";

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  // Only POST allowed
  if (req.method !== "POST") {
    return res.status(405).json({
      decision: "DENY",
      reason: "method_not_allowed",
    });
  }

  try {
    /**
     * ------------------------------------------------------------
     * Transport-level protection (outer boundary)
     * ------------------------------------------------------------
     */
    const expectedToken = process.env.ADAPTER_GATEWAY_TOKEN;
    const authHeader = req.headers.authorization;

    if (!expectedToken || authHeader !== `Bearer ${expectedToken}`) {
      return res.status(401).json({
        decision: "DENY",
        reason: "unauthorized_gateway_access",
      });
    }

    /**
     * ------------------------------------------------------------
     * Envelope
     * ------------------------------------------------------------
     */
    const envelope = req.body;

    if (!envelope) {
      return res.status(400).json({
        decision: "DENY",
        reason: "missing_request_body",
      });
    }

    /**
     * ------------------------------------------------------------
     * Enforcement (PEP)
     * ------------------------------------------------------------
     */
    const cfg = loadAdapterConfig();

    const result = await gateAndForward(cfg, envelope);

    if (result.decision !== "PERMIT") {
      return res.status(403).json(result);
    }

    return res.status(200).json(result);

  } catch (err) {
    console.error("adapter_internal_error:", err);

    return res.status(500).json({
      decision: "DENY",
      reason: "adapter_internal_error",
    });
  }
}
