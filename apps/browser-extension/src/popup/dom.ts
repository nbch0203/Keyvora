// Tiny DOM helpers. Text is always inserted as text nodes (never parsed as HTML) so vault data cannot inject markup.

type Child = Node | string | number | null | undefined | false;
type AttrValue = string | number | boolean | null | undefined | ((ev: Event) => void);

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs?: Record<string, AttrValue> | null,
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v === null || v === undefined || v === false) continue;
    if (typeof v === "function") el.addEventListener(k.replace(/^on/, ""), v as EventListener);
    else if (k === "class") el.className = String(v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, String(v));
  }
  append(el, ...children);
  return el;
}

export function append(el: Element, ...children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    el.append(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  }
}

let uid = 0;
export function nextId(prefix: string): string {
  return `${prefix}-${++uid}`;
}

/** Label + control + optional hint, correctly associated for assistive technologies. */
export function field(label: string, control: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement, hint?: string): HTMLDivElement {
  if (!control.id) control.id = nextId("f");
  const hintEl = hint ? h("p", { class: "hint", id: `${control.id}-hint` }, hint) : null;
  if (hintEl) control.setAttribute("aria-describedby", hintEl.id);
  return h("div", { class: "field" }, h("label", { for: control.id }, label), control, hintEl);
}

/** Password input with a show/hide toggle. */
export function secretInput(attrs: Record<string, AttrValue> = {}): { wrap: HTMLDivElement; input: HTMLInputElement } {
  const input = h("input", { type: "password", autocomplete: "off", spellcheck: "false", ...attrs });
  const toggle = h("button", { type: "button", class: "btn small ghost", "aria-pressed": "false" }, "Mostrar");
  toggle.addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    toggle.textContent = show ? "Ocultar" : "Mostrar";
    toggle.setAttribute("aria-pressed", String(show));
  });
  return { wrap: h("div", { class: "secret" }, input, toggle), input };
}

export function labeledSecret(label: string, attrs: Record<string, AttrValue> = {}, hint?: string): { el: HTMLDivElement; input: HTMLInputElement } {
  const { wrap, input } = secretInput(attrs);
  if (!input.id) input.id = nextId("s");
  const hintEl = hint ? h("p", { class: "hint", id: `${input.id}-hint` }, hint) : null;
  if (hintEl) input.setAttribute("aria-describedby", hintEl.id);
  return { el: h("div", { class: "field" }, h("label", { for: input.id }, label), wrap, hintEl), input };
}

export function errorBox(): { el: HTMLParagraphElement; show(text: string): void; clear(): void } {
  const el = h("p", { class: "error", role: "alert", hidden: true });
  return {
    el,
    show(text: string) {
      el.textContent = text;
      el.hidden = false;
    },
    clear() {
      el.textContent = "";
      el.hidden = true;
    },
  };
}

let toastTimer: ReturnType<typeof setTimeout> | null = null;
export function toast(text: string, kind: "info" | "error" = "info"): void {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = text;
  el.className = `toast ${kind}`;
  el.hidden = false;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.hidden = true;
  }, 4000);
}

/** Modal confirmation built on <dialog>. Resolves true only on the explicit confirm button. */
export function confirmDialog(opts: { title: string; body: Child[]; confirm: string; cancel?: string; danger?: boolean }): Promise<boolean> {
  return new Promise((resolve) => {
    const titleId = nextId("dlg");
    const ok = h("button", { type: "button", class: opts.danger ? "btn danger" : "btn primary" }, opts.confirm);
    const no = h("button", { type: "button", class: "btn" }, opts.cancel ?? "Cancelar");
    const dlg = h("dialog", { "aria-labelledby": titleId, class: "dialog" }, h("h2", { id: titleId }, opts.title), h("div", { class: "dialog-body" }, ...opts.body), h("div", { class: "actions" }, no, ok));
    const finish = (v: boolean) => {
      dlg.close();
      dlg.remove();
      resolve(v);
    };
    ok.addEventListener("click", () => finish(true));
    no.addEventListener("click", () => finish(false));
    dlg.addEventListener("cancel", (e) => {
      e.preventDefault();
      finish(false);
    });
    document.body.append(dlg);
    dlg.showModal();
    no.focus();
  });
}

/** Disables a button while an async action runs (prevents double submits). */
export async function busy<T>(btn: HTMLButtonElement, fn: () => Promise<T>, label?: string): Promise<T> {
  const old = btn.textContent;
  btn.disabled = true;
  btn.setAttribute("aria-busy", "true");
  if (label) btn.textContent = label;
  try {
    return await fn();
  } finally {
    btn.disabled = false;
    btn.removeAttribute("aria-busy");
    btn.textContent = old;
  }
}

export function downloadText(fileName: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const a = h("a", { href: url, download: fileName, hidden: true });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
