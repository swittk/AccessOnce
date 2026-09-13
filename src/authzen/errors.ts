/** Error representing an invalid AuthZEN request or response payload. */
export class AuthZenRequestError extends Error {
  /** HTTP-compatible status for malformed AuthZEN payloads. */
  readonly status = 400;
}

/** Error returned when an AuthZEN HTTPS request fails at the transport layer. */
export class AuthZenHttpError extends Error {
  /** HTTP response status returned by the remote PDP. */
  readonly status: number;
  /** Raw text body returned by the remote PDP. */
  readonly body: string;

  /** Create one transport error while preserving status/body for callers that need protocol handling. */
  constructor(status: number, body: string) {
    super(`AuthZEN HTTP ${status}: ${body || "request failed"}`);
    this.status = status;
    this.body = body;
  }
}
