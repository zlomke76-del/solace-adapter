import express from "express";
import crypto from "crypto";
import { loadAdapterConfigFromEnv } from "./config.js";
import { authorizeOnly } from "./gate.js";
import { asMessage } from "./errors.js";

const app = express();

const cfg = loadAdapterConfigFromEnv();

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    adapterId: cfg.adapterId,
  });
});

app.post("/v1/authorize", express.json(), async (req, res) => {
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
          body: req.body,
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

export default app;
