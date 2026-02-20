// api/v1/gate.ts

import type { VercelRequest, VercelResponse } from "@vercel/node";
import { gateAndForward } from "../../src/gate";
import { loadAdapterConfig } from "../../src/config";

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "method_not_allowed" });
  }

  try {
    // 🔐 Transport-level protection
    const authHeader = req.headers.authorization;
    const expectedToken = process.env.ADAPTER_GATEWAY_TOKEN;

    if (!expectedToken || authHeader !== `Bearer ${expectedToken}`) {
      return res.status(401).json({
        decision: "DENY",
        reason: "unauthorized_gateway_access",
      });
    }

    const envelope = req.body;

    const cfg = loadAdapterConfig();

    const result = await gateAndForward(cfg, envelope);

    if (result.decision !== "PERMIT") {
      return res.status(403).json(result);
    }

    return res.status(200).json(result);

  } catch (err) {
    console.error("adapter_error:", err);

    return res.status(500).json({
      decision: "DENY",
      reason: "adapter_internal_error",
    });
  }
}
