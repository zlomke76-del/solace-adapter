// src/errors.ts

export type ErrorDetails = Record<string, unknown>;

function formatDetails(details?: ErrorDetails): string {
  try {
    if (!details) return "";
    return " :: " + JSON.stringify(details);
  } catch {
    return "";
  }
}

export class ConfigError extends Error {
  details?: ErrorDetails;
  constructor(message: string, details?: ErrorDetails) {
    super(message + formatDetails(details));
    this.name = "ConfigError";
    this.details = details;
  }
}

export class FailClosedError extends Error {
  details?: ErrorDetails;
  constructor(message: string, details?: ErrorDetails) {
    super(message + formatDetails(details));
    this.name = "FailClosedError";
    this.details = details;
  }
}

export class ForwardingError extends Error {
  details?: ErrorDetails;
  constructor(message: string, details?: ErrorDetails) {
    super(message + formatDetails(details));
    this.name = "ForwardingError";
    this.details = details;
  }
}

export function asMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  try {
    return JSON.stringify(err);
  } catch {
    return "unknown_error";
  }
}
