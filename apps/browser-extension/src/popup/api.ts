// Popup → service worker calls ({v:1,type,payload} → {ok,data}|{ok:false,error}).
import { PROTOCOL_VERSION, type MessageType, type Reply } from "../shared/messages.ts";

export class ApiError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "ApiError";
    this.code = code;
  }
}

export async function call<T = unknown>(type: MessageType, payload?: unknown): Promise<T> {
  let reply: Reply<T> | undefined;
  try {
    reply = (await chrome.runtime.sendMessage({ v: PROTOCOL_VERSION, type, payload })) as Reply<T> | undefined;
  } catch {
    throw new ApiError("UNKNOWN");
  }
  if (!reply || typeof reply !== "object") throw new ApiError("UNKNOWN");
  if (!reply.ok) throw new ApiError(reply.error);
  return reply.data;
}

export function codeOf(e: unknown): string {
  return e instanceof ApiError ? e.code : "UNKNOWN";
}
