// Popup entry: routing between screens. The popup holds no vault state; everything goes through the service worker.
import { call, codeOf } from "./api.ts";
import type { App, PopupStatus } from "./app.ts";
import { toast } from "./dom.ts";
import { errorText } from "./text.ts";
import { renderConflicts, renderDetail, renderEdit, renderGenerateFill, renderList } from "./views/entries.ts";
import { renderSettings } from "./views/settings.ts";
import { renderCreate, renderRecoveryKey, renderRecoveryUnlock, renderRestore, renderUnlock } from "./views/setup.ts";

const root = document.getElementById("app") as HTMLElement;

const app: App = {
  root,
  generator: { length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, excludeAmbiguous: false, requireEachClass: true },
  show(...nodes: Node[]) {
    root.replaceChildren(...nodes);
    const heading = root.querySelector<HTMLElement>("h1");
    heading?.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  },
  handleLocked(e: unknown): boolean {
    if (codeOf(e) !== "LOCKED") return false;
    renderUnlock(app, "La bóveda se ha bloqueado por inactividad.");
    return true;
  },
  async lock() {
    try {
      await call("lock");
    } finally {
      renderUnlock(app);
    }
  },
  nav: {
    async home() {
      let status: PopupStatus;
      try {
        status = await call<PopupStatus>("status");
      } catch (e) {
        root.replaceChildren();
        toast(errorText(codeOf(e)), "error");
        return;
      }
      if (status.unlocked) return renderList(app);
      if (status.hasVault) return renderUnlock(app);
      if (status.pendingRemote) return renderUnlock(app, "Se encontró tu bóveda en Google Drive. Introduce tu contraseña maestra para usarla en este navegador.");
      return renderCreate(app, status);
    },
    create: () => renderCreate(app, null),
    unlock: (message?: string) => renderUnlock(app, message),
    recoveryUnlock: () => renderRecoveryUnlock(app),
    restore: () => renderRestore(app),
    recoveryKey: (key, onDone, title) => renderRecoveryKey(app, key, onDone, title),
    list: () => renderList(app),
    detail: (id) => renderDetail(app, id),
    edit: (entry, prefillUrl) => renderEdit(app, entry, prefillUrl),
    conflicts: (id) => renderConflicts(app, id),
    generateFill: (tab) => renderGenerateFill(app, tab),
    settings: () => renderSettings(app),
  },
};

// User interaction in the popup counts as activity for the auto-lock (throttled ping).
let lastPing = Date.now();
const ping = () => {
  if (Date.now() - lastPing < 30_000) return;
  lastPing = Date.now();
  call("status").catch(() => undefined);
};
document.addEventListener("pointerdown", ping, { passive: true });
document.addEventListener("keydown", ping, { passive: true });

void app.nav.home();
