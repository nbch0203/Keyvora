// Popup ↔ service worker messaging (docs/CONTRACTS.md §5).

export const PROTOCOL_VERSION = 1 as const;

export const MESSAGE_TYPES = [
  "status", "create", "unlock", "unlockRecovery", "lock", "list", "search", "get", "createEntry", "updateEntry",
  "deleteEntry", "resolveConflict", "generate", "matchesForActiveTab", "fill", "generateAndFill", "changePassword",
  "resetWithRecovery", "rotateRecovery", "settings.get", "settings.set", "export", "import", "sync.connect",
  "sync.now", "sync.status", "sync.disconnect",
  // Added after the security review (ADR-013, key rotation):
  "rotateDataKey", "sync.adoptRemoteKeys",
] as const;

export type MessageType = (typeof MESSAGE_TYPES)[number];

export interface RequestEnvelope {
  v: typeof PROTOCOL_VERSION;
  type: MessageType;
  payload?: unknown;
}

export type Reply<T = unknown> = { ok: true; data: T } | { ok: false; error: string };

const TYPE_SET = new Set<string>(MESSAGE_TYPES);

/** Returns the envelope when it is well formed, otherwise null. */
export function parseEnvelope(msg: unknown): RequestEnvelope | null {
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) return null;
  const m = msg as Record<string, unknown>;
  if (m["v"] !== PROTOCOL_VERSION) return null;
  if (typeof m["type"] !== "string" || !TYPE_SET.has(m["type"])) return null;
  for (const k of Object.keys(m)) if (k !== "v" && k !== "type" && k !== "payload") return null;
  return { v: PROTOCOL_VERSION, type: m["type"] as MessageType, payload: m["payload"] };
}

/** Minimal view of chrome.runtime.MessageSender. */
export interface SenderLike {
  id?: string | undefined;
  url?: string | undefined;
  origin?: string | undefined;
}

function parts(u: string): { origin: string; page: string } | null {
  try {
    const p = new URL(u);
    // URL.origin is "null" for chrome-extension:/moz-extension: outside the browser, so build it explicitly.
    const origin = `${p.protocol}//${p.host}`;
    return { origin, page: `${origin}${p.pathname}` };
  } catch {
    return null;
  }
}

/**
 * Only the extension's own popup page may talk to the service worker: same extension id and the popup URL
 * (query string and fragment ignored). Content scripts, web pages, other extension pages and other extensions
 * are rejected.
 */
export function isTrustedSender(sender: SenderLike | undefined, runtimeId: string, popupUrl: string): boolean {
  if (!sender || !runtimeId || sender.id !== runtimeId) return false;
  if (typeof sender.url !== "string") return false;
  const expected = parts(popupUrl);
  const actual = parts(sender.url);
  if (!expected || !actual || expected.page !== actual.page) return false;
  if (sender.origin !== undefined && sender.origin !== "null" && sender.origin !== expected.origin) return false;
  return true;
}

export function okReply<T>(data: T): Reply<T> {
  return { ok: true, data };
}

export function errReply(code: string): Reply<never> {
  return { ok: false, error: code };
}
