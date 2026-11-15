// Shared popup state and navigation contract (implemented in main.ts) used by the views.
import type { CredentialMatch, Entry, GeneratorOptions } from "../core/types.ts";
import { h } from "./dom.ts";

export interface PopupStatus {
  hasVault: boolean;
  unlocked: boolean;
  pendingRemote: boolean;
  autoLockMinutes: number;
  sync: { configured: boolean; connected: boolean };
}

export interface ActiveTabMatches {
  fillable: boolean;
  origin: string | null;
  host: string | null;
  matches: CredentialMatch[];
}

export interface Nav {
  home(): Promise<void>;
  create(): void;
  unlock(message?: string): void;
  recoveryUnlock(): void;
  restore(): void;
  recoveryKey(key: string, onDone: () => void, title?: string): void;
  list(): Promise<void>;
  detail(id: string): Promise<void>;
  edit(entry: Entry | null, prefillUrl?: string | null): void;
  conflicts(id: string): Promise<void>;
  generateFill(tab: ActiveTabMatches): void;
  settings(): Promise<void>;
}

export interface App {
  root: HTMLElement;
  nav: Nav;
  /** Default generator options used by the edit form and "generar y rellenar". */
  generator: GeneratorOptions;
  /** Replaces the screen content and moves focus to its heading. */
  show(...nodes: Node[]): void;
  /** Handles LOCKED globally (back to the unlock screen); returns true when handled. */
  handleLocked(e: unknown): boolean;
  lock(): Promise<void>;
}

/** Common header: back button (optional), title, settings and lock buttons. */
export function topBar(app: App, title: string, opts: { back?: () => void; actions?: boolean } = {}): HTMLElement {
  const left = opts.back
    ? h("button", { type: "button", class: "btn icon", "aria-label": "Volver", onclick: () => opts.back?.() }, "←")
    : h("span", { class: "logo", "aria-hidden": "true" }, "🔑");
  const right = opts.actions === false
    ? null
    : h(
        "div",
        { class: "bar-actions" },
        h("button", { type: "button", class: "btn icon", "aria-label": "Ajustes", title: "Ajustes", onclick: () => void app.nav.settings() }, "⚙"),
        h("button", { type: "button", class: "btn small", onclick: () => void app.lock() }, "Bloquear"),
      );
  return h("header", { class: "bar" }, left, h("h1", { tabindex: "-1" }, title), right);
}
