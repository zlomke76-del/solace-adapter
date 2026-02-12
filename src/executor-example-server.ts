// src/executor-example-server.ts
// Example CLOSED executor service showing how to verify adapter receipts.
// This is a reference stub you can copy into any executor.
// In production:
// - put this behind private networking (no public ingress)
// - allow only adapter identity at network/mTLS layer
// - enforce idempotency in a real database constraint

import express from "express";
import type { JsonObject } from "./types";
import { verifyExecutorRequest } from "./executorVerifier";
import { ConfigError } from "./errors";

const app = express();
app.use(express.json({ limit: "1mb" }));

const EXPECTED_SERVICE = process.env.EXECUTOR_SERVICE_NAME || "payments";
const RECEIPT_PUB = process.env.SOLACE_ADAPTER_RECEIPT_PUBLIC_KEY_PEM;

if (!RECEIPT_PUB || !RECEIPT_PUB.includes("BEGIN")) {
  throw new ConfigError("executor_missing_SOLACE_ADAPTER_RECEIPT_PUBLIC_KEY_PEM");
}

// naive in-memory idempotency for demo only
const SEEN = new Set<string>();

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: `executor:${EXPECTED_SERVICE}` });
});

app.post("/internal/execute", (req, res) => {
  const receiptHeader = req.header("x-solace-receipt") || undefined;

  const body = req.body as { intent?: JsonObject; execute?: JsonObject };
  const execute = body?.execute;

  const v = verifyExecutorRequest({
    receiptHeader,
    receiptPublicKeyPem: RECEIPT_PUB,
    expectedService: EXPECTED_SERVICE,
    execute,
  });

  if (!v.ok) {
    return res.status(200).json({
      decision: "DENY",
      reason: v.reason || "receipt_verification_failed",
    });
  }

  // idempotency (demo): use receiptId
  const receiptId = v.receipt!.receiptId;
  if (SEEN.has(receiptId)) {
    return res.status(200).json({
      decision: "DENY",
      reason: "idempotency_replay_detected",
    });
  }
  SEEN.add(receiptId);

  // EXECUTE SIDE EFFECT HERE
  // In demo, we just return success.
  return res.status(200).json({
    decision: "PERMIT",
    executed: true,
    service: EXPECTED_SERVICE,
    executeHash: v.executeHash,
    receiptId,
  });
});

const PORT = process.env.PORT ? Number(process.env.PORT) : 9090;
app.listen(PORT, () => {
  console.log(`[BOOT] executor:${EXPECTED_SERVICE} listening on ${PORT}`);
});
