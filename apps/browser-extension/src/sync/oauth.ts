// OAuth 2.0 implicit flow through `identity.launchWebAuthFlow` (ADR-008). No client secret; the access token
// (≈1 h) lives only in `storage.session` and is never logged.
import { KvError } from "../shared/errors.ts";
import type { KeyValueArea } from "../shared/storage.ts";
import type { FetchLike, TokenProvider } from "./google-drive.ts";

export const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.appdata";
export const GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke";
export const TOKEN_KEY = "sync.token";

export interface AuthUrlParams {
  clientId: string;
  redirectUri: string;
  state: string;
  interactive: boolean;
}

export function buildAuthUrl(p: AuthUrlParams): string {
  const q = new URLSearchParams({
    client_id: p.clientId,
    response_type: "token",
    redirect_uri: p.redirectUri,
    scope: DRIVE_SCOPE,
    state: p.state,
    include_granted_scopes: "false",
  });
  if (!p.interactive) q.set("prompt", "none");
  return `${GOOGLE_AUTH_ENDPOINT}?${q}`;
}

export interface TokenResult {
  accessToken: string;
  expiresAt: number;
}

/** Parses the redirect of the implicit flow. Any anomaly → AUTH_REQUIRED. */
export function parseAuthRedirect(redirectUrl: string, expectedState: string, redirectUri: string, nowMs: number): TokenResult {
  let u: URL;
  let base: URL;
  try {
    u = new URL(redirectUrl);
    base = new URL(redirectUri);
  } catch {
    throw new KvError("AUTH_REQUIRED");
  }
  if (u.origin !== base.origin) throw new KvError("AUTH_REQUIRED");
  const params = new URLSearchParams(u.hash.startsWith("#") ? u.hash.slice(1) : u.hash);
  if (params.get("error") || params.get("state") !== expectedState) throw new KvError("AUTH_REQUIRED");
  const token = params.get("access_token");
  const type = params.get("token_type");
  const scopes = (params.get("scope") ?? "").split(/\s+/);
  if (!token || (type !== null && type.toLowerCase() !== "bearer") || !scopes.includes(DRIVE_SCOPE)) {
    throw new KvError("AUTH_REQUIRED");
  }
  const expiresIn = Number(params.get("expires_in") ?? "3600");
  const secs = Number.isFinite(expiresIn) && expiresIn > 0 ? Math.min(expiresIn, 86_400) : 3600;
  return { accessToken: token, expiresAt: nowMs + secs * 1000 };
}

export interface IdentityLike {
  launchWebAuthFlow(details: { url: string; interactive: boolean }): Promise<string | undefined>;
  getRedirectURL(path?: string): string;
}

export interface GoogleAuthOptions {
  clientId: string;
  identity: IdentityLike;
  session: KeyValueArea;
  now: () => number;
  randomState?: () => string;
  fetch?: FetchLike;
}

function randomState(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export class GoogleAuth implements TokenProvider {
  readonly #o: GoogleAuthOptions;

  constructor(opts: GoogleAuthOptions) {
    this.#o = opts;
  }

  async #cached(): Promise<string | null> {
    const t = (await this.#o.session.get([TOKEN_KEY]))[TOKEN_KEY] as Partial<TokenResult> | undefined;
    if (t && typeof t.accessToken === "string" && typeof t.expiresAt === "number" && t.expiresAt - 60_000 > this.#o.now()) {
      return t.accessToken;
    }
    return null;
  }

  async #launch(interactive: boolean): Promise<string> {
    // Must match the authorized redirect URI registered in Google Cloud (infrastructure/google-drive/README.md).
    const redirectUri = this.#o.identity.getRedirectURL();
    const state = (this.#o.randomState ?? randomState)();
    let redirect: string | undefined;
    try {
      redirect = await this.#o.identity.launchWebAuthFlow({ url: buildAuthUrl({ clientId: this.#o.clientId, redirectUri, state, interactive }), interactive });
    } catch {
      throw new KvError("AUTH_REQUIRED");
    }
    if (!redirect) throw new KvError("AUTH_REQUIRED");
    const t = parseAuthRedirect(redirect, state, redirectUri, this.#o.now());
    await this.#o.session.set({ [TOKEN_KEY]: t });
    return t.accessToken;
  }

  /** Cached token, else a silent (non-interactive) attempt, else AUTH_REQUIRED. */
  async getToken(): Promise<string> {
    return (await this.#cached()) ?? (await this.#launch(false));
  }

  /** Interactive consent (user clicked "Conectar"). */
  async connect(): Promise<void> {
    await this.#launch(true);
  }

  async invalidate(_token: string): Promise<void> {
    await this.#o.session.remove([TOKEN_KEY]);
  }

  /** Forgets the token and, best effort, revokes it at Google. */
  async disconnect(): Promise<void> {
    const token = await this.#cached();
    await this.#o.session.remove([TOKEN_KEY]);
    if (token && this.#o.fetch) {
      try {
        await this.#o.fetch(GOOGLE_REVOKE_ENDPOINT, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token }).toString(),
        });
      } catch {
        /* best effort */
      }
    }
  }
}
