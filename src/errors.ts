// src/errors.ts

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export class FailClosedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FailClosedError";
  }
}

export class ForwardingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ForwardingError";
  }
}

export function asMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  return "unknown_error";
}
