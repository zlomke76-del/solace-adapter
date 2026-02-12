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
