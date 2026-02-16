// src/server.ts

import express from "express";
import { loadAdapterConfigFromEnv } from "./config.js";
import { authorizeOnly } from "./gate.js";
import { asMessage } from "./errors.js";

const app = express();

// ------------------------------------------------------------
// 🔍 RUNTIME ENV PROOF (REMOVE LATER)
// ------------------------------------------------------------
console.log("=== ENV DEBUG START ===");
console.log("SOLACE_ADAPTER_ID:", process.env.SOLACE_ADAPTER_ID);
console.log("NODE_ENV:", process.env.NODE_ENV);
console.log("=== ENV DEBUG END ===");

// ------------------------------------------------------------
// Load config
// ------------------------------------------------------------
const cfg = loadAdapterConfigFromEnv();

// ------------------------------------------------------------
// Health
// ------------------------------------------------------------
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    adapterId: cfg.adapterId,
  });
});

// ------------------------------------------------------------
// Authorize (JSON parsed — safe)
// ------------------------------------------------------------
app.post(
  "/v1/authorize",
  express.json(),
  async (req, res) => {
    try {
      const result = await authorizeOnly(cfg, req.body);
      res.json(result);
    } catch (e) {
      res.status(500).json({
        decision: "DENY",
        reason: asMessage(e),
      });
    }
  }
);

// ------------------------------------------------------------
// Execute (RAW passthrough — CRITICAL)
// ------------------------------------------------------------
app.post(
  "/v1/execute",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const coreResponse = await fetch(
        `${cfg.core.coreBaseUrl}/v1/execute`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...cfg.core.headers,
          },
          body: req.body,
        }
      );

      const text = await coreResponse.text();

      res.status(coreResponse.status).send(text);
    } catch (e) {
      res.status(500).json({
        decision: "DENY",
        reason: asMessage(e),
      });
    }
  }
);

const PORT = process.env.PORT || 8788;

app.listen(PORT, () => {
  console.log(`Solace Adapter listening on ${PORT}`);
});
