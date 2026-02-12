// src/server.ts

import express from "express";
import { asMessage } from "./errors";
import { loadConfig } from "./config";
import { handleGate } from "./gate";

const app = express();
app.use(express.json());

// JSON parse error guard (TS-safe)
app.use((err: any, _req: any, res: any, next: any) => {
  if (err instanceof SyntaxError && err?.status === 400 && "body" in err) {
    return res.status(400).json({
      decision: "DENY",
      reason: "invalid_json",
      message: err.message,
    });
  }
  next(err);
});

const config = loadConfig();

app.get("/health", (_req, res) => {
  res.status(200).json({
    status: "ok",
    service: "solace-adapter",
  });
});

app.post("/v1/gate", async (req, res) => {
  try {
    const result = await handleGate(req.body, config);

    if (result.decision !== "PERMIT") {
      return res.status(200).json({
        decision: "DENY",
        reason: result.reason || "denied",
      });
    }

    return res.status(200).json({
      decision: "PERMIT",
      service: result.service,
      receipt: result.receipt,
    });
  } catch (e) {
    return res.status(200).json({
      decision: "DENY",
      reason: "adapter_error",
      error: asMessage(e),
    });
  }
});

const PORT = Number(process.env.PORT || 8788);
app.listen(PORT, () => {
  console.log(`solace-adapter listening on ${PORT}`);
});
