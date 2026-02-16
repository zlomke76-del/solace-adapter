// src/server.ts

import express from "express";
import { loadAdapterConfigFromEnv } from "./config.js";
import { gateAndForward, authorizeOnly } from "./gate.js";
import { asMessage } from "./errors.js";

const app = express();
app.use(express.json());

// ------------------------------------------------------------
// JSON parse guard
// ------------------------------------------------------------
app.use((err: any, _req: any, res: any, next: any) => {
  if (err instanceof SyntaxError) {
    return res.status(400).json({
      decision: "DENY",
      reason: "invalid_json",
    });
  }
  next(err);
});

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
// Authorize (Phase 1)
// ------------------------------------------------------------
app.post("/v1/authorize", async (req, res) => {
  try {
    const result = await authorizeOnly(cfg, req.body);
    res.json(result);
  } catch (e) {
    res.status(500).json({
      decision: "DENY",
      reason: asMessage(e),
    });
  }
});

// ------------------------------------------------------------
// Gate + Forward (Phase 2)
// ------------------------------------------------------------
app.post("/v1/execute", async (req, res) => {
  try {
    const result = await gateAndForward(cfg, req.body);
    res.json(result);
  } catch (e) {
    res.status(500).json({
      decision: "DENY",
      reason: asMessage(e),
    });
  }
});

const PORT = process.env.PORT || 8788;
app.listen(PORT, () => {
  console.log(`Solace Adapter listening on ${PORT}`);
});
