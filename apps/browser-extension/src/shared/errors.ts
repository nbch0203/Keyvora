import { errorCode } from "../core/types.ts";

/** Extension-level error codes (in addition to the core codes of CONTRACTS.md §1.2 and the sync codes of §6). */
export type ExtErrorCode =
  | "BAD_REQUEST"
  | "VAULT_EXISTS"
  | "NO_VAULT"
  | "CORE_UNAVAILABLE"
  | "NO_ACTIVE_TAB"
  | "NOT_FILLABLE"
  | "NO_MATCH"
  | "CONFIRMATION_REQUIRED"
  | "INJECTION_FAILED"
  | "SYNC_NOT_CONFIGURED"
  | "SYNC_NOT_CONNECTED"
  | "REMOTE_EMPTY"
  | "CONFLICT_RETRY_EXHAUSTED"
  | "NETWORK"
  | "AUTH_REQUIRED"
  | "RATE_LIMITED"
  | "REMOTE_ERROR"
  | "UNKNOWN";

/** An error whose message is exactly one stable code. Never carries user data. */
export class KvError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "KvError";
    this.code = code;
  }
}

const KNOWN_EXT = new Set<string>([
  "BAD_REQUEST", "VAULT_EXISTS", "NO_VAULT", "CORE_UNAVAILABLE", "NO_ACTIVE_TAB", "NOT_FILLABLE", "NO_MATCH",
  "CONFIRMATION_REQUIRED", "INJECTION_FAILED", "SYNC_NOT_CONFIGURED", "SYNC_NOT_CONNECTED", "REMOTE_EMPTY",
  "CONFLICT_RETRY_EXHAUSTED", "NETWORK", "AUTH_REQUIRED", "RATE_LIMITED", "REMOTE_ERROR",
]);

/**
 * Maps any thrown value to a stable code. Unknown errors become `UNKNOWN`: their message is never forwarded
 * (it could contain data from a page or a library).
 */
export function toErrorCode(e: unknown): string {
  if (e instanceof KvError) return e.code;
  const core = errorCode(e);
  if (core !== "UNKNOWN") return core;
  if (e instanceof Error && KNOWN_EXT.has(e.message)) return e.message;
  if (e && typeof e === "object" && "code" in e) {
    const c = (e as { code: unknown }).code;
    if (typeof c === "string" && KNOWN_EXT.has(c)) return c;
  }
  return "UNKNOWN";
}
