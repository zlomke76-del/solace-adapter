export class AdapterError extends Error {
  code: string;
  status: number;

  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export class FailClosedError extends AdapterError {
  constructor(message = "fail_closed") {
    super("FAIL_CLOSED", message, 503);
  }
}
