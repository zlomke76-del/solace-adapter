// src/server.ts

import express from "express";
import crypto from "crypto";
import { loadAdapterConfigFromEnv } from "./config.js";
import { authorizeOnly } from "./gate.js";
import { asMessage } from "./errors.js";

const app = express();

// ------------------------------------------------------------
// 🔍 ENV DEBUG (REMOVE WHEN STABLE)
// ------------------------------------------------------------
console.log("=== ENV DEBUG START ===");
console.log("SOLACE_ADAPTER_ID:", process.env.SOLACE_ADAPTER_ID);
console.log("NODE_ENV:", process.env.NODE_ENV);
console.log("=== ENV DEBUG END ===");

// ------------------------------------------------------------
// Load config (throws if invalid — good)
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
    const requestId = crypto.randomUUID();

    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      cfg.core.timeoutMs
    );

    try {
      const coreResponse = await fetch(
        `${cfg.core.coreBaseUrl}/v1/execute`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-solace-adapter-id": cfg.adapterId,
            "x-solace-request-id": requestId,
            ...cfg.core.headers,
          },
          body: req.body, // 🔒 forward raw buffer untouched
          signal: controller.signal,
        }
      );

      clearTimeout(timeout);

      const text = await coreResponse.text();

      res
        .status(coreResponse.status)
        .setHeader("x-solace-request-id", requestId)
        .send(text);
    } catch (e: any) {
      clearTimeout(timeout);

      // Fail closed if Core unreachable
      res.status(503).json({
        decision: "DENY",
        reason:
          e?.name === "AbortError"
            ? "core_timeout"
            : "core_unreachable",
        requestId,
      });
    }
  }
);

// ------------------------------------------------------------
// IMPORTANT: DO NOT call app.listen() on Vercel
// ------------------------------------------------------------

export default app;
