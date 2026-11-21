// Create vault, recovery key, unlock (password / recovery key), restore from encrypted backup.
import { call, codeOf } from "../api.ts";
import type { App, PopupStatus } from "../app.ts";
import { copySecret } from "../clipboard.ts";
import { busy, errorBox, field, h, labeledSecret, toast } from "../dom.ts";
import { errorText, masterErrorText } from "../text.ts";

const MIN_MASTER = 12;
const RECOMMENDED_MASTER = 16;

function masterHint(input: HTMLInputElement, out: HTMLElement): void {
  const n = [...input.value].length;
  if (n === 0) out.textContent = `Mínimo ${MIN_MASTER} caracteres. Lo ideal es una frase de varias palabras (${RECOMMENDED_MASTER} o más).`;
  else if (n < MIN_MASTER) out.textContent = `Demasiado corta: ${n} de ${MIN_MASTER} caracteres mínimos.`;
  else if (n < RECOMMENDED_MASTER) out.textContent = `Válida. Una frase más larga (${RECOMMENDED_MASTER}+ caracteres) es aún más segura.`;
  else out.textContent = "Longitud adecuada.";
}

/** New master password + confirmation, with the rules shown live. Returns a validator. */
export function newMasterFields(
  labels = { pw: "Contraseña maestra", confirm: "Repite la contraseña maestra" },
  ids: { pw?: string; confirm?: string } = {},
) {
  const pw = labeledSecret(labels.pw, { autocomplete: "new-password", required: true, minlength: MIN_MASTER, id: ids.pw });
  const confirm = labeledSecret(labels.confirm, { autocomplete: "new-password", required: true, id: ids.confirm });
  const hint = h("p", { class: "hint", "aria-live": "polite" });
  masterHint(pw.input, hint);
  pw.input.addEventListener("input", () => masterHint(pw.input, hint));
  return {
    nodes: [pw.el, hint, confirm.el],
    pw: pw.input,
    confirm: confirm.input,
    validate(): string | null {
      if ([...pw.input.value].length < MIN_MASTER) return `La contraseña maestra debe tener al menos ${MIN_MASTER} caracteres.`;
      if (pw.input.value !== confirm.input.value) return "Las contraseñas no coinciden.";
      return null;
    },
  };
}

function irreversibleWarning(): HTMLElement {
  return h(
    "div",
    { class: "warning", role: "note" },
    h("strong", null, "Importante: "),
    "Keyvora no puede recuperar tu contraseña maestra. Si pierdes la contraseña maestra y también la clave de recuperación, perderás el acceso a tus datos de forma irreversible.",
  );
}

export function renderCreate(app: App, status: PopupStatus | null): void {
  const m = newMasterFields(undefined, { pw: "create-password", confirm: "create-confirm" });
  const err = errorBox();
  const submit = h("button", { type: "submit", class: "btn primary block" }, "Crear bóveda");
  const form = h("form", { novalidate: true }, ...m.nodes, irreversibleWarning(), err.el, submit);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    err.clear();
    const problem = m.validate();
    if (problem) return err.show(problem);
    void busy(submit, async () => {
      try {
        const { recoveryKey } = await call<{ recoveryKey: string }>("create", { master: m.pw.value });
        m.pw.value = "";
        m.confirm.value = "";
        app.nav.recoveryKey(recoveryKey, () => void app.nav.home());
      } catch (e2) {
        err.show(masterErrorText(codeOf(e2)));
      }
    }, "Creando… (puede tardar unos segundos)");
  });

  const alt = h("div", { class: "alt-actions" },
    h("button", { type: "button", class: "btn link", onclick: () => app.nav.restore() }, "Restaurar desde una copia cifrada"),
    status?.sync.configured
      ? h("button", { type: "button", class: "btn link", onclick: (ev) => void connectDrive(app, ev.currentTarget as HTMLButtonElement, err) }, "Ya uso Keyvora: conectar Google Drive")
      : null,
  );

  app.show(
    h("header", { class: "bar" }, h("span", { class: "logo", "aria-hidden": "true" }, "🔑"), h("h1", { tabindex: "-1" }, "Crear tu bóveda")),
    h("main", { class: "content" },
      h("p", null, "Tus contraseñas se cifran en este dispositivo con una contraseña maestra que solo tú conoces."),
      form,
      alt,
    ),
  );
}

async function connectDrive(app: App, btn: HTMLButtonElement, err: ReturnType<typeof errorBox>): Promise<void> {
  err.clear();
  await busy(btn, async () => {
    try {
      toast("Se abrirá una ventana de Google. Si este panel se cierra, vuelve a abrir Keyvora al terminar.");
      await call("sync.connect");
      await app.nav.home();
    } catch (e) {
      err.show(errorText(codeOf(e)));
    }
  }, "Conectando…");
}

/** Shows the recovery key once; continuing requires ticking "La he guardado" and typing its last group. */
export function renderRecoveryKey(app: App, key: string, onDone: () => void, title = "Tu clave de recuperación"): void {
  const groups = key.split("-");
  const last = (groups.at(-1) ?? "").toUpperCase();
  const keyBox = h("output", { class: "recovery-key", "data-testid": "recovery-key", "aria-label": "Clave de recuperación" }, key);
  const saved = h("input", { type: "checkbox", id: "rk-saved" });
  const typed = h("input", { type: "text", id: "rk-last", autocomplete: "off", spellcheck: "false", maxlength: 8, inputmode: "text" });
  const cont = h("button", { type: "button", class: "btn primary block", disabled: true }, "Continuar");
  const update = () => {
    cont.disabled = !(saved.checked && typed.value.trim().toUpperCase() === last);
  };
  saved.addEventListener("change", update);
  typed.addEventListener("input", update);
  cont.addEventListener("click", () => {
    keyBox.textContent = "";
    onDone();
  });
  app.show(
    h("header", { class: "bar" }, h("span", { class: "logo", "aria-hidden": "true" }, "🔑"), h("h1", { tabindex: "-1" }, title)),
    h("main", { class: "content" },
      h("p", null, "Esta clave permite entrar si olvidas la contraseña maestra. ", h("strong", null, "Solo se muestra esta vez."), " Guárdala fuera de línea (en papel o en un lugar seguro), nunca junto a tu contraseña maestra."),
      keyBox,
      h("div", { class: "row" }, h("button", { type: "button", class: "btn small", onclick: () => void copySecret(key, "Clave de recuperación") }, "Copiar")),
      h("div", { class: "check" }, saved, h("label", { for: "rk-saved" }, "La he guardado en un lugar seguro")),
      field("Escribe el último grupo de la clave (4 caracteres) para confirmar", typed),
      cont,
    ),
  );
}

export function renderUnlock(app: App, message?: string): void {
  const pw = labeledSecret("Contraseña maestra", { autocomplete: "current-password", id: "unlock-password", required: true });
  const err = errorBox();
  const submit = h("button", { type: "submit", class: "btn primary block" }, "Desbloquear");
  const form = h("form", { novalidate: true }, pw.el, err.el, submit);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    err.clear();
    if (!pw.input.value) return err.show("Introduce tu contraseña maestra.");
    void busy(submit, async () => {
      try {
        await call("unlock", { master: pw.input.value });
        pw.input.value = "";
        await app.nav.home();
      } catch (e2) {
        err.show(errorText(codeOf(e2)));
        pw.input.select();
      }
    }, "Desbloqueando…");
  });
  app.show(
    h("header", { class: "bar" }, h("span", { class: "logo", "aria-hidden": "true" }, "🔑"), h("h1", { tabindex: "-1" }, "Desbloquear Keyvora")),
    h("main", { class: "content" },
      message ? h("p", { class: "info" }, message) : null,
      form,
      h("div", { class: "alt-actions" }, h("button", { type: "button", class: "btn link", onclick: () => app.nav.recoveryUnlock() }, "Usar clave de recuperación")),
    ),
  );
  pw.input.focus();
}

export function renderRecoveryUnlock(app: App): void {
  const rk = h("textarea", { id: "rk-input", rows: 3, autocomplete: "off", spellcheck: "false", required: true, class: "mono" });
  const m = newMasterFields({ pw: "Nueva contraseña maestra", confirm: "Repite la nueva contraseña maestra" });
  const err = errorBox();
  const submit = h("button", { type: "submit", class: "btn primary block" }, "Restablecer y desbloquear");
  const form = h("form", { novalidate: true },
    field("Clave de recuperación", rk, "Los guiones y espacios son opcionales."),
    h("p", null, "Por seguridad, al usar la clave de recuperación debes fijar una nueva contraseña maestra."),
    ...m.nodes, err.el, submit);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    err.clear();
    if (!rk.value.trim()) return err.show("Introduce la clave de recuperación.");
    const problem = m.validate();
    if (problem) return err.show(problem);
    void busy(submit, async () => {
      try {
        const { recoveryKey } = await call<{ recoveryKey: string }>("unlockRecovery", { recoveryKey: rk.value, newMaster: m.pw.value });
        rk.value = "";
        m.pw.value = "";
        m.confirm.value = "";
        toast("Contraseña maestra restablecida. Guarda la nueva clave de recuperación: la usada ya no funciona.");
        app.nav.recoveryKey(recoveryKey, () => void app.nav.home(), "Nueva clave de recuperación");
      } catch (e2) {
        err.show(masterErrorText(codeOf(e2)));
      }
    }, "Restableciendo…");
  });
  app.show(
    h("header", { class: "bar" }, h("button", { type: "button", class: "btn icon", "aria-label": "Volver", onclick: () => app.nav.unlock() }, "←"), h("h1", { tabindex: "-1" }, "Clave de recuperación")),
    h("main", { class: "content" }, form),
  );
}

export function renderRestore(app: App): void {
  const file = h("input", { type: "file", accept: ".json,application/json", id: "restore-file", required: true });
  const pw = labeledSecret("Contraseña maestra de esa bóveda", { autocomplete: "current-password", required: true });
  const err = errorBox();
  const submit = h("button", { type: "submit", class: "btn primary block" }, "Restaurar");
  const form = h("form", { novalidate: true }, field("Copia cifrada (.json)", file), pw.el, err.el, submit);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    err.clear();
    const f = file.files?.[0];
    if (!f) return err.show("Elige el archivo de la copia.");
    if (!pw.input.value) return err.show("Introduce la contraseña maestra.");
    void busy(submit, async () => {
      try {
        const container = await f.text();
        await call("import", { container, master: pw.input.value });
        pw.input.value = "";
        toast("Bóveda restaurada.");
        await app.nav.home();
      } catch (e2) {
        err.show(errorText(codeOf(e2)));
      }
    }, "Restaurando…");
  });
  app.show(
    h("header", { class: "bar" }, h("button", { type: "button", class: "btn icon", "aria-label": "Volver", onclick: () => void app.nav.home() }, "←"), h("h1", { tabindex: "-1" }, "Restaurar copia")),
    h("main", { class: "content" }, h("p", null, "Restaura una copia exportada desde Keyvora. Se comprobará con su contraseña maestra antes de guardarla."), form),
  );
}
