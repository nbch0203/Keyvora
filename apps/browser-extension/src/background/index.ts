// Service worker entry point (Chromium) / background module script (Firefox).
// Listeners are registered synchronously at top level; the WASM core is loaded lazily on first use.
import { loadCore } from "../core/index.ts";
import { isTrustedSender } from "../shared/messages.ts";
import { chromeArea, type ChromeStorageAreaLike } from "../shared/storage.ts";
import { GoogleDriveRemoteStore } from "../sync/google-drive.ts";
import { GoogleAuth } from "../sync/oauth.ts";
import { AUTOLOCK_ALARM, AutoLock } from "./autolock.ts";
import { createHandlers, dispatch, type TabInfo } from "./handlers.ts";
import { fillLoginInPage, fillNewPasswordInPage, type FillArgs, type FillResult } from "./inject.ts";
import { SettingsStore } from "./settings-store.ts";
import { SYNC_RETRY_ALARM, SyncController } from "./sync-controller.ts";
import { VaultService } from "./vault-service.ts";

const POPUP_URL = chrome.runtime.getURL("popup.html");
const local = chromeArea(chrome.storage.local as unknown as ChromeStorageAreaLike);
const session = chromeArea(chrome.storage.session as unknown as ChromeStorageAreaLike);

// The session DEK must be readable only by extension pages, never by content scripts (Chromium only API).
const sessionArea = chrome.storage.session as unknown as { setAccessLevel?: (o: { accessLevel: string }) => Promise<void> };
if (typeof sessionArea.setAccessLevel === "function") {
  sessionArea.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => undefined);
}

const settings = new SettingsStore(local);
const autolock = new AutoLock({
  alarms: chrome.alarms,
  session,
  now: () => Date.now(),
  minutes: async () => (await settings.get()).autoLockMinutes,
});

let sync: SyncController | null = null;
const vaults = new VaultService({
  core: loadCore,
  local,
  session,
  autolock,
  now: () => Date.now(),
  randomUUID: () => crypto.randomUUID(),
  onUnlocked: () => sync?.onUnlocked(),
  onMutation: () => sync?.markDirty(),
});

const clientId = __KEYVORA_GOOGLE_CLIENT_ID__;
const boundFetch = (url: string, init?: RequestInit) => fetch(url, init);
const auth = clientId
  ? new GoogleAuth({
      clientId,
      identity: {
        launchWebAuthFlow: (details) => chrome.identity.launchWebAuthFlow(details),
        getRedirectURL: (path) => chrome.identity.getRedirectURL(path),
      },
      session,
      now: () => Date.now(),
      fetch: boundFetch,
    })
  : null;
sync = new SyncController({
  auth,
  remote: auth ? new GoogleDriveRemoteStore({ fetch: boundFetch, tokens: auth }) : null,
  vaults,
  local,
  session,
  alarms: chrome.alarms,
});

async function getTab(tabId: number): Promise<TabInfo | null> {
  try {
    const t = await chrome.tabs.get(tabId);
    return typeof t.id === "number" ? { id: t.id, url: t.url } : null;
  } catch {
    return null;
  }
}

async function getActiveTab(): Promise<TabInfo | null> {
  const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
  return t && typeof t.id === "number" ? { id: t.id, url: t.url } : null;
}

async function inject(tabId: number, kind: "login" | "register", args: FillArgs): Promise<FillResult> {
  const results = await chrome.scripting.executeScript({
    target: { tabId, frameIds: [0] },
    func: kind === "login" ? fillLoginInPage : fillNewPasswordInPage,
    args: [args],
  });
  return results[0]?.result as FillResult;
}

const handlers = createHandlers({
  core: loadCore,
  vaults,
  settings,
  autolock,
  sync,
  getActiveTab,
  getTab,
  inject,
  now: () => Date.now(),
});

let rejectedMessages = 0;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!isTrustedSender(sender, chrome.runtime.id, POPUP_URL)) {
    rejectedMessages++;
    return false; // ignored: no reply, no side effects
  }
  void dispatch(handlers, message).then(sendResponse);
  return true;
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTOLOCK_ALARM) {
    void (async () => {
      if (await autolock.expired()) await vaults.lock();
      else await autolock.reschedule();
    })();
  } else if (alarm.name === SYNC_RETRY_ALARM) {
    void sync?.onRetryAlarm();
  }
});

if (__KEYVORA_TEST__) {
  // E2E builds only (scripts/build.mjs --e2e). Normal builds drop this block; the build verifies it.
  (globalThis as Record<string, unknown>)["__keyvoraTest"] = {
    handle: (type: string, payload?: unknown, tabId?: number) =>
      dispatch(handlers, { v: 1, type, payload }, tabId === undefined ? {} : { tabId }),
    fill: (tabId: number, entryId: string, confirmed = false, confirmedHost?: string) =>
      dispatch(handlers, { v: 1, type: "fill", payload: { entryId, confirmed, confirmedHost } }, { tabId }),
    rejectedMessages: () => rejectedMessages,
  };
}
