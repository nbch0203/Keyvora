import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { MemoryArea } from "../../src/shared/storage.ts";
import { buildAuthUrl, DRIVE_SCOPE, GoogleAuth, parseAuthRedirect, TOKEN_KEY } from "../../src/sync/oauth.ts";
import { FakeClock } from "./helpers/fakes.ts";

const REDIRECT = "https://abcdefghijklmnop.chromiumapp.org/";
const CLIENT = "123-abc.apps.googleusercontent.com";

function redirectWith(params: Record<string, string>): string {
  return `${REDIRECT}#${new URLSearchParams(params)}`;
}

describe("OAuth implicit flow", () => {
  test("auth URL requests a token with the drive.appdata scope only", () => {
    const u = new URL(buildAuthUrl({ clientId: CLIENT, redirectUri: REDIRECT, state: "S1", interactive: true }));
    assert.equal(u.origin + u.pathname, "https://accounts.google.com/o/oauth2/v2/auth");
    assert.equal(u.searchParams.get("response_type"), "token");
    assert.equal(u.searchParams.get("scope"), DRIVE_SCOPE);
    assert.equal(u.searchParams.get("redirect_uri"), REDIRECT);
    assert.equal(u.searchParams.get("state"), "S1");
    assert.equal(u.searchParams.get("prompt"), "select_account");
    const silent = new URL(buildAuthUrl({ clientId: CLIENT, redirectUri: REDIRECT, state: "S1", interactive: false }));
    assert.equal(silent.searchParams.get("prompt"), "none");
  });

  test("parses a valid redirect", () => {
    const t = parseAuthRedirect(redirectWith({ access_token: "tok", token_type: "Bearer", expires_in: "3599", scope: DRIVE_SCOPE, state: "S1" }), "S1", REDIRECT, 1000);
    assert.deepEqual(t, { accessToken: "tok", expiresAt: 1000 + 3599 * 1000 });
  });

  test("rejects state mismatch, errors, missing scope, other origins", () => {
    const ok = { access_token: "tok", token_type: "Bearer", expires_in: "3600", scope: DRIVE_SCOPE, state: "S1" };
    const bad = [
      redirectWith({ ...ok, state: "S2" }),
      redirectWith({ error: "access_denied", state: "S1" }),
      redirectWith({ ...ok, scope: "https://www.googleapis.com/auth/drive" }),
      redirectWith({ ...ok, access_token: "" }),
      `https://evil.example/#${new URLSearchParams(ok)}`,
      "garbage",
    ];
    for (const r of bad) assert.throws(() => parseAuthRedirect(r, "S1", REDIRECT, 0), /AUTH_REQUIRED/, r);
  });

  function auth(flow: (url: string, interactive: boolean) => Promise<string | undefined>) {
    const clock = new FakeClock();
    const session = new MemoryArea();
    const launches: Array<{ url: string; interactive: boolean }> = [];
    const a = new GoogleAuth({
      clientId: CLIENT,
      identity: {
        launchWebAuthFlow: async (d) => {
          launches.push(d);
          return flow(d.url, d.interactive);
        },
        getRedirectURL: () => REDIRECT,
      },
      session,
      now: clock.now,
      randomState: () => "STATE",
    });
    return { a, clock, session, launches };
  }
  const grant = async () => redirectWith({ access_token: "tok-1", token_type: "Bearer", expires_in: "3600", scope: DRIVE_SCOPE, state: "STATE" });

  test("connect is interactive and caches the token in session storage only", async () => {
    const { a, session, launches } = auth(grant);
    await a.connect();
    assert.equal(launches[0]!.interactive, true);
    assert.equal((session.data.get(TOKEN_KEY) as { accessToken: string }).accessToken, "tok-1");
    assert.equal(await a.getToken(), "tok-1");
    assert.equal(launches.length, 1, "cached token reused");
  });

  test("an expired token triggers a silent (non-interactive) attempt", async () => {
    const { a, clock, launches } = auth(grant);
    await a.connect();
    clock.advance(3600 * 1000);
    assert.equal(await a.getToken(), "tok-1");
    assert.equal(launches[1]!.interactive, false);
    assert.equal(new URL(launches[1]!.url).searchParams.get("prompt"), "none");
  });

  test("failed silent attempt → AUTH_REQUIRED; invalidate drops the token", async () => {
    const { a } = auth(async () => {
      throw new Error("The user did not approve access.");
    });
    await assert.rejects(a.getToken(), /AUTH_REQUIRED/);
    const ok = auth(grant);
    await ok.a.connect();
    await ok.a.invalidate("tok-1");
    assert.equal(ok.session.data.has(TOKEN_KEY), false);
  });
});
