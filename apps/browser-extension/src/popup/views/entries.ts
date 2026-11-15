// List + suggestions, detail, edit/create with generator, conflicts, "generar y rellenar".
import type { ConflictSnapshot, CredentialMatch, Entry, EntrySummary, GeneratorOptions } from "../../core/types.ts";
import { call, codeOf } from "../api.ts";
import { topBar, type ActiveTabMatches, type App } from "../app.ts";
import { copySecret } from "../clipboard.ts";
import { busy, confirmDialog, errorBox, field, h, nextId, secretInput, toast } from "../dom.ts";
import { entropyLabel, errorText, FILL_TEXT, formatDate } from "../text.ts";
import { keysChangedPanel } from "./keys.ts";

async function activeTab(): Promise<ActiveTabMatches> {
  try {
    return await call<ActiveTabMatches>("matchesForActiveTab");
  } catch {
    return { fillable: false, origin: null, host: null, matches: [] };
  }
}

function hostOfUrl(u: string): string {
  try {
    return new URL(u.includes("://") ? u : `https://${u}`).host;
  } catch {
    return u;
  }
}

/** Fills after the confirmation required for sameSite matches (shows the real host, warns on IDN). */
export async function fillWithConfirmation(app: App, match: CredentialMatch): Promise<void> {
  let confirmed = false;
  if (match.level === "sameSite") {
    confirmed = await confirmDialog({
      title: "¿Rellenar en este sitio?",
      body: [
        h("p", null, "La entrada se guardó para ", h("strong", null, hostOfUrl(match.matchedUrl)), ", pero la página actual es:"),
        h("p", { class: "host" }, match.pageHost),
        match.pageIsIdn
          ? h("p", { class: "warning" }, "Atención: el dominio contiene caracteres internacionales (se muestra en punycode). Comprueba que es exactamente el sitio que esperas; podría imitar a otro.")
          : null,
        h("p", null, "Rellena solo si confías en este subdominio."),
      ],
      confirm: "Rellenar",
    });
    if (!confirmed) return;
  }
  try {
    const { result } = await call<{ result: string }>("fill", { entryId: match.entry.id, confirmed, confirmedHost: match.pageHost });
    toast(FILL_TEXT[result] ?? FILL_TEXT["no-form"]!, result === "filled" ? "info" : "error");
  } catch (e) {
    if (!app.handleLocked(e)) toast(errorText(codeOf(e)), "error");
  }
}

function entryRow(app: App, e: EntrySummary, match?: CredentialMatch): HTMLLIElement {
  const open = h(
    "button",
    { type: "button", class: "entry-main", onclick: () => void app.nav.detail(e.id) },
    h("span", { class: "entry-title" }, e.title),
    h("span", { class: "entry-sub" }, e.username || e.urls[0] || ""),
    e.hasConflicts ? h("span", { class: "badge warn" }, "Conflicto") : null,
    match?.level === "sameSite" ? h("span", { class: "badge" }, "Mismo sitio") : null,
  );
  const fill = match
    ? h("button", { type: "button", class: "btn small primary", "aria-label": `Rellenar ${e.title}`, onclick: () => void fillWithConfirmation(app, match) }, "Rellenar")
    : null;
  return h("li", { class: "entry" }, open, fill);
}

export async function renderList(app: App): Promise<void> {
  const search = h("input", { type: "search", id: "search", placeholder: "Buscar por título, usuario o web", autocomplete: "off", "aria-label": "Buscar" });
  const suggestions = h("section", { class: "section", "aria-labelledby": "sugg-h" });
  const all = h("ul", { class: "entries", "aria-labelledby": "all-h" });
  const empty = h("p", { class: "muted", hidden: true }, "No hay entradas.");
  const add = h("button", { type: "button", class: "btn primary", onclick: () => app.nav.edit(null, tab.fillable ? tab.origin : null) }, "+ Añadir");
  let tab: ActiveTabMatches = { fillable: false, origin: null, host: null, matches: [] };
  const alerts = h("div", { class: "alerts" });

  app.show(
    topBar(app, "Keyvora"),
    h("main", { class: "content" },
      alerts,
      h("div", { class: "row" }, search, add),
      suggestions,
      h("section", { class: "section" }, h("h2", { id: "all-h" }, "Todas las entradas"), all, empty),
    ),
  );

  const renderEntries = (list: EntrySummary[]) => {
    all.replaceChildren(...list.map((e) => entryRow(app, e)));
    empty.hidden = list.length > 0;
    empty.textContent = search.value ? "Sin resultados." : "Todavía no hay entradas. Pulsa «+ Añadir».";
  };

  try {
    const [entries, t] = await Promise.all([call<EntrySummary[]>("list"), activeTab()]);
    tab = t;
    renderEntries(entries);
  } catch (e) {
    if (!app.handleLocked(e)) toast(errorText(codeOf(e)), "error");
    return;
  }

  call<{ keysChanged: boolean }>("sync.status")
    .then((s) => {
      if (s.keysChanged) alerts.replaceChildren(keysChangedPanel(app, () => alerts.replaceChildren()));
    })
    .catch(() => undefined);

  const heading = h("h2", { id: "sugg-h" }, "Sugerencias para este sitio");
  if (!tab.fillable) {
    suggestions.replaceChildren(heading, h("p", { class: "muted" }, "Esta página no admite autorrelleno (solo HTTPS)."));
  } else {
    const items = tab.matches.map((m) => entryRow(app, m.entry, m));
    suggestions.replaceChildren(
      heading,
      h("p", { class: "muted host-line" }, tab.host ?? ""),
      items.length ? h("ul", { class: "entries" }, ...items) : h("p", { class: "muted" }, "No hay entradas para este sitio."),
      h("button", { type: "button", class: "btn block", onclick: () => app.nav.generateFill(tab) }, "Generar contraseña y rellenar registro"),
    );
  }

  let timer: ReturnType<typeof setTimeout> | null = null;
  search.addEventListener("input", () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      call<EntrySummary[]>("search", { query: search.value })
        .then(renderEntries)
        .catch((e) => {
          if (!app.handleLocked(e)) toast(errorText(codeOf(e)), "error");
        });
    }, 150);
  });
  search.focus();
}

function maskedSecret(value: string, label: string): HTMLElement {
  const out = h("span", { class: "mono secret-value", "aria-label": `${label} oculta` }, "••••••••••");
  let shown = false;
  const toggle = h("button", { type: "button", class: "btn small ghost", "aria-pressed": "false" }, "Mostrar");
  toggle.addEventListener("click", () => {
    shown = !shown;
    out.textContent = shown ? value : "••••••••••";
    out.setAttribute("aria-label", shown ? label : `${label} oculta`);
    toggle.textContent = shown ? "Ocultar" : "Mostrar";
    toggle.setAttribute("aria-pressed", String(shown));
  });
  const copy = h("button", { type: "button", class: "btn small", onclick: () => void copySecret(value, label) }, "Copiar");
  return h("div", { class: "secret-row" }, out, toggle, copy);
}

function kv(label: string, value: Node | string): HTMLElement {
  return h("div", { class: "kv" }, h("dt", null, label), h("dd", null, value));
}

export async function renderDetail(app: App, id: string): Promise<void> {
  let entry: Entry;
  let tab: ActiveTabMatches;
  try {
    [entry, tab] = await Promise.all([call<Entry>("get", { id }), activeTab()]);
  } catch (e) {
    if (!app.handleLocked(e)) {
      toast(errorText(codeOf(e)), "error");
      await app.nav.list();
    }
    return;
  }
  const match = tab.matches.find((m) => m.entry.id === id);
  const history = entry.passwordHistory.length
    ? h("details", { class: "history" },
        h("summary", null, `Historial de contraseñas (${entry.passwordHistory.length})`),
        h("ul", null, ...entry.passwordHistory.map((it) => h("li", null, h("span", { class: "muted" }, `Retirada: ${formatDate(it.retiredAt)}`), maskedSecret(it.password, "Contraseña anterior")))))
    : null;

  const del = h("button", { type: "button", class: "btn danger" }, "Eliminar");
  del.addEventListener("click", async () => {
    const ok = await confirmDialog({
      title: "¿Eliminar entrada?",
      body: [h("p", null, "Se eliminará «", h("strong", null, entry.title), "». El borrado se propagará a tus otros dispositivos al sincronizar.")],
      confirm: "Eliminar",
      danger: true,
    });
    if (!ok) return;
    await busy(del, async () => {
      try {
        await call("deleteEntry", { id });
        toast("Entrada eliminada.");
        await app.nav.list();
      } catch (e) {
        if (!app.handleLocked(e)) toast(errorText(codeOf(e)), "error");
      }
    });
  });

  app.show(
    topBar(app, entry.title, { back: () => void app.nav.list() }),
    h("main", { class: "content" },
      entry.conflicts.length
        ? h("div", { class: "warning" }, `Esta entrada tiene ${entry.conflicts.length} versión(es) en conflicto de otros dispositivos. `,
            h("button", { type: "button", class: "btn link", onclick: () => void app.nav.conflicts(id) }, "Revisar conflictos"))
        : null,
      h("dl", { class: "details" },
        kv("Usuario", entry.username
          ? h("div", { class: "secret-row" }, h("span", { class: "mono" }, entry.username), h("button", { type: "button", class: "btn small", onclick: () => void copySecret(entry.username, "Usuario") }, "Copiar"))
          : h("span", { class: "muted" }, "—")),
        kv("Contraseña", entry.password ? maskedSecret(entry.password, "Contraseña") : h("span", { class: "muted" }, "—")),
        kv("Webs", entry.urls.length ? h("ul", { class: "urls" }, ...entry.urls.map((u) => h("li", { class: "mono" }, u))) : h("span", { class: "muted" }, "—")),
        entry.notes ? kv("Notas", h("pre", { class: "notes" }, entry.notes)) : null,
        kv("Modificada", formatDate(entry.updatedAt)),
      ),
      history,
      h("div", { class: "actions" },
        match ? h("button", { type: "button", class: "btn primary", onclick: () => void fillWithConfirmation(app, match) }, "Rellenar") : null,
        h("button", { type: "button", class: "btn", onclick: () => app.nav.edit(entry) }, "Editar"),
        del,
      ),
    ),
  );
}

/** Generator controls; `onChange` receives the options whenever they change. */
export function generatorPanel(app: App, onUse: ((pw: string) => void) | null): { el: HTMLElement; options(): GeneratorOptions } {
  const o = app.generator;
  const lenId = nextId("len");
  const length = h("input", { type: "range", id: lenId, min: 8, max: 128, value: o.length ?? 20 });
  const lengthNum = h("input", { type: "number", min: 8, max: 128, value: o.length ?? 20, "aria-label": "Longitud", class: "num" });
  const box = (label: string, checked: boolean) => {
    const id = nextId("gen");
    const input = h("input", { type: "checkbox", id, checked });
    return { input, el: h("div", { class: "check" }, input, h("label", { for: id }, label)) };
  };
  const lower = box("Minúsculas (a-z)", o.lowercase ?? true);
  const upper = box("Mayúsculas (A-Z)", o.uppercase ?? true);
  const digits = box("Dígitos (0-9)", o.digits ?? true);
  const symbols = box("Símbolos (!#$…)", o.symbols ?? true);
  const ambiguous = box("Excluir caracteres ambiguos (I l 1 O 0 o |)", o.excludeAmbiguous ?? false);
  const preview = h("output", { class: "mono preview", "aria-live": "polite" });
  const entropy = h("p", { class: "hint", "aria-live": "polite" });
  const err = errorBox();
  let current = "";

  const options = (): GeneratorOptions => ({
    length: Math.min(128, Math.max(8, Number(lengthNum.value) || 20)),
    lowercase: lower.input.checked,
    uppercase: upper.input.checked,
    digits: digits.input.checked,
    symbols: symbols.input.checked,
    excludeAmbiguous: ambiguous.input.checked,
    requireEachClass: true,
  });

  const regenerate = async () => {
    err.clear();
    const opts = options();
    if (!opts.lowercase && !opts.uppercase && !opts.digits && !opts.symbols) {
      err.show("Selecciona al menos un tipo de carácter.");
      return;
    }
    app.generator = opts;
    try {
      const r = await call<{ password: string; entropyBits: number }>("generate", { options: opts });
      current = r.password;
      if (onUse) preview.textContent = r.password;
      entropy.textContent = `Entropía estimada: ${Math.round(r.entropyBits)} bits (${entropyLabel(r.entropyBits)}).`;
    } catch (e) {
      err.show(errorText(codeOf(e)));
    }
  };

  length.addEventListener("input", () => {
    lengthNum.value = length.value;
    void regenerate();
  });
  lengthNum.addEventListener("change", () => {
    length.value = String(options().length);
    lengthNum.value = length.value;
    void regenerate();
  });
  for (const b of [lower, upper, digits, symbols, ambiguous]) b.input.addEventListener("change", () => void regenerate());

  const el = h("fieldset", { class: "generator" },
    h("legend", null, "Generador de contraseñas"),
    h("div", { class: "field" }, h("label", { for: lenId }, "Longitud"), h("div", { class: "row" }, length, lengthNum)),
    lower.el, upper.el, digits.el, symbols.el, ambiguous.el,
    onUse ? preview : null,
    entropy,
    err.el,
    onUse
      ? h("div", { class: "row" },
          h("button", { type: "button", class: "btn small", onclick: () => void regenerate() }, "Generar otra"),
          h("button", { type: "button", class: "btn small primary", onclick: () => current && onUse(current) }, "Usar esta contraseña"))
      : null,
  );
  void regenerate();
  return { el, options };
}

export function renderEdit(app: App, entry: Entry | null, prefillUrl?: string | null): void {
  const title = h("input", { type: "text", required: true, maxlength: 256, value: entry?.title ?? "", autocomplete: "off" });
  const username = h("input", { type: "text", maxlength: 512, value: entry?.username ?? "", autocomplete: "off", spellcheck: "false" });
  const pw = secretInput({ value: entry?.password ?? "", maxlength: 4096 });
  pw.input.id = nextId("pw");
  const urls = h("textarea", { rows: 2, class: "mono", spellcheck: "false" });
  urls.value = entry ? entry.urls.join("\n") : (prefillUrl ?? "");
  const notes = h("textarea", { rows: 3, maxlength: 16384 });
  notes.value = entry?.notes ?? "";
  const genSlot = h("div");
  const genBtn = h("button", { type: "button", class: "btn small" }, "Generador");
  genBtn.addEventListener("click", () => {
    if (genSlot.firstChild) return genSlot.replaceChildren();
    genSlot.replaceChildren(generatorPanel(app, (p) => {
      pw.input.value = p;
      genSlot.replaceChildren();
      toast("Contraseña generada aplicada; guarda para conservarla.");
    }).el);
  });
  const err = errorBox();
  const save = h("button", { type: "submit", class: "btn primary" }, "Guardar");
  const form = h("form", { novalidate: true },
    field("Título", title),
    field("Usuario o correo", username),
    h("div", { class: "field" }, h("label", { for: pw.input.id }, "Contraseña"), pw.wrap, h("div", { class: "row" }, genBtn)),
    genSlot,
    field("Webs (una por línea)", urls, "Ejemplo: https://ejemplo.com. Se usan para sugerir y rellenar solo en esos sitios."),
    field("Notas", notes),
    err.el,
    h("div", { class: "actions" }, h("button", { type: "button", class: "btn", onclick: () => (entry ? void app.nav.detail(entry.id) : void app.nav.list()) }, "Cancelar"), save),
  );
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    err.clear();
    if (!title.value.trim()) return err.show("El título es obligatorio.");
    const input = {
      title: title.value.trim(),
      username: username.value,
      password: pw.input.value,
      urls: urls.value.split(/\r?\n/).map((u) => u.trim()).filter(Boolean),
      notes: notes.value,
    };
    void busy(save, async () => {
      try {
        const saved = entry ? await call<Entry>("updateEntry", { id: entry.id, input }) : await call<Entry>("createEntry", { input });
        toast("Entrada guardada.");
        await app.nav.detail(saved.id);
      } catch (e2) {
        if (!app.handleLocked(e2)) err.show(errorText(codeOf(e2)));
      }
    });
  });
  app.show(topBar(app, entry ? "Editar entrada" : "Nueva entrada", { back: () => (entry ? void app.nav.detail(entry.id) : void app.nav.list()) }), h("main", { class: "content" }, form));
  title.focus();
}

function snapshotView(s: Pick<ConflictSnapshot, "title" | "username" | "password" | "urls" | "notes">): HTMLElement {
  return h("dl", { class: "details compact" },
    kv("Título", s.title),
    kv("Usuario", s.username || "—"),
    kv("Contraseña", s.password ? maskedSecret(s.password, "Contraseña") : "—"),
    kv("Webs", s.urls.join(", ") || "—"),
    s.notes ? kv("Notas", h("pre", { class: "notes" }, s.notes)) : null,
  );
}

export async function renderConflicts(app: App, id: string): Promise<void> {
  let entry: Entry;
  try {
    entry = await call<Entry>("get", { id });
  } catch (e) {
    if (!app.handleLocked(e)) toast(errorText(codeOf(e)), "error");
    return;
  }
  const resolve = async (btn: HTMLButtonElement, choice: number) => {
    await busy(btn, async () => {
      try {
        const r = await call<Entry | null>("resolveConflict", { id, choice });
        toast("Conflicto resuelto.");
        if (r) await app.nav.detail(r.id);
        else await app.nav.list();
      } catch (e) {
        if (!app.handleLocked(e)) toast(errorText(codeOf(e)), "error");
      }
    });
  };
  const keep = h("button", { type: "button", class: "btn primary" }, "Mantener la actual");
  keep.addEventListener("click", () => void resolve(keep, -1));
  const cards = entry.conflicts.map((c, i) => {
    const btn = h("button", { type: "button", class: c.kind === "deletion" ? "btn danger" : "btn" }, c.kind === "deletion" ? "Aceptar la eliminación" : "Usar esta versión");
    btn.addEventListener("click", async () => {
      if (c.kind === "deletion") {
        const ok = await confirmDialog({ title: "¿Eliminar la entrada?", body: [h("p", null, "Otro dispositivo eliminó esta entrada. Si aceptas, se eliminará también aquí.")], confirm: "Eliminar", danger: true });
        if (!ok) return;
      }
      await resolve(btn, i);
    });
    return h("section", { class: "card" },
      h("h3", null, c.kind === "deletion" ? "Eliminada en otro dispositivo" : "Versión de otro dispositivo"),
      h("p", { class: "muted" }, `${formatDate(c.updatedAt)} · dispositivo ${c.updatedBy.slice(0, 8)}`),
      c.kind === "edit" ? snapshotView(c) : null,
      btn);
  });
  app.show(
    topBar(app, "Conflictos", { back: () => void app.nav.detail(id) }),
    h("main", { class: "content" },
      h("p", null, "Se editó la misma entrada en varios dispositivos a la vez. No se ha perdido nada: elige qué versión conservar."),
      h("section", { class: "card current" }, h("h3", null, "Versión actual"), h("p", { class: "muted" }, formatDate(entry.updatedAt)), snapshotView(entry), keep),
      ...cards,
    ),
  );
}

export function renderGenerateFill(app: App, tab: ActiveTabMatches): void {
  const title = h("input", { type: "text", required: true, maxlength: 256, value: tab.host ?? "", autocomplete: "off" });
  const username = h("input", { type: "text", maxlength: 512, autocomplete: "off", spellcheck: "false" });
  const gen = generatorPanel(app, null);
  const err = errorBox();
  const go = h("button", { type: "submit", class: "btn primary block" }, "Generar, guardar y rellenar");
  const form = h("form", { novalidate: true },
    h("p", null, "Se generará una contraseña aleatoria, se guardará como entrada para ", h("strong", null, tab.origin ?? ""), " y se escribirá en los campos de contraseña del formulario de registro."),
    field("Título", title),
    field("Usuario o correo (opcional)", username),
    gen.el,
    err.el,
    go,
  );
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    err.clear();
    if (!title.value.trim()) return err.show("El título es obligatorio.");
    void busy(go, async () => {
      try {
        const r = await call<{ entryId: string; result: string }>("generateAndFill", { title: title.value.trim(), username: username.value, options: gen.options() });
        toast(r.result === "filled" ? "Contraseña generada, guardada y rellenada." : `Entrada guardada. ${FILL_TEXT[r.result] ?? ""}`, r.result === "filled" ? "info" : "error");
        await app.nav.detail(r.entryId);
      } catch (e2) {
        if (!app.handleLocked(e2)) err.show(errorText(codeOf(e2)));
      }
    });
  });
  app.show(topBar(app, "Generar y rellenar", { back: () => void app.nav.list() }), h("main", { class: "content" }, form));
  title.focus();
}
