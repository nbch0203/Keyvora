// Settings: auto-lock, master password, recovery key, encrypted backup, Google Drive sync.
import { call, codeOf } from "../api.ts";
import { topBar, type App } from "../app.ts";
import { busy, confirmDialog, downloadText, errorBox, field, h, labeledSecret, toast } from "../dom.ts";
import { errorText, formatDate, KDF_WEAKENED_TEXT, RECOVERY_KEY_CHANGED_TEXT } from "../text.ts";
import { keysChangedPanel } from "./keys.ts";
import { newMasterFields } from "./setup.ts";

interface SyncStatusView {
  configured: boolean;
  connected: boolean;
  syncing: boolean;
  dirty: boolean;
  lastSyncAt: number | null;
  lastError: string | null;
  rollbackWarning: boolean;
  keysChanged: boolean;
  lastMerge: { added: number; updated: number; removed: number; newConflicts: number; keyringAdopted: boolean; keyringConflict: boolean; kdfWeakened: boolean; recoveryKeyChanged: boolean } | null;
}

function section(title: string, ...children: Array<Node | null>): HTMLElement {
  const id = `sec-${title.replace(/\W+/g, "-").toLowerCase()}`;
  return h("section", { class: "section card", "aria-labelledby": id }, h("h2", { id }, title), ...children);
}

function autoLockSection(app: App, minutes: number): HTMLElement {
  const input = h("input", { type: "number", min: 1, max: 60, step: 1, value: minutes, required: true, class: "num" });
  const err = errorBox();
  const save = h("button", { type: "submit", class: "btn small primary" }, "Guardar");
  const form = h("form", { novalidate: true }, field("Bloquear tras (minutos de inactividad, 1–60)", input), err.el, save);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    err.clear();
    const v = Number(input.value);
    if (!Number.isInteger(v) || v < 1 || v > 60) return err.show("Introduce un número entero entre 1 y 60.");
    void busy(save, async () => {
      try {
        await call("settings.set", { autoLockMinutes: v });
        toast("Bloqueo automático actualizado.");
      } catch (e2) {
        if (!app.handleLocked(e2)) err.show(errorText(codeOf(e2)));
      }
    });
  });
  return section("Bloqueo automático", form);
}

function masterSection(app: App): HTMLElement {
  const current = labeledSecret("Contraseña maestra actual", { autocomplete: "current-password" });
  const m = newMasterFields({ pw: "Nueva contraseña maestra", confirm: "Repite la nueva contraseña maestra" });
  const err = errorBox();
  const save = h("button", { type: "submit", class: "btn small primary" }, "Cambiar contraseña");
  const form = h("form", { novalidate: true }, current.el, ...m.nodes, err.el, save);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    err.clear();
    if (!current.input.value) return err.show("Introduce la contraseña actual.");
    const problem = m.validate();
    if (problem) return err.show(problem);
    void busy(save, async () => {
      try {
        await call("changePassword", { current: current.input.value, next: m.pw.value });
        current.input.value = m.pw.value = m.confirm.value = "";
        toast("Contraseña maestra cambiada.");
      } catch (e2) {
        if (!app.handleLocked(e2)) err.show(errorText(codeOf(e2)));
      }
    }, "Cambiando…");
  });

  // Forgotten current password while unlocked: prove possession of the recovery key instead.
  const rk = h("textarea", { rows: 2, class: "mono", autocomplete: "off", spellcheck: "false" });
  const m2 = newMasterFields({ pw: "Nueva contraseña maestra", confirm: "Repite la nueva contraseña maestra" });
  const err2 = errorBox();
  const save2 = h("button", { type: "submit", class: "btn small" }, "Restablecer con la clave");
  const form2 = h("form", { novalidate: true }, field("Clave de recuperación", rk), ...m2.nodes, err2.el, save2);
  form2.addEventListener("submit", (e) => {
    e.preventDefault();
    err2.clear();
    if (!rk.value.trim()) return err2.show("Introduce la clave de recuperación.");
    const problem = m2.validate();
    if (problem) return err2.show(problem);
    void busy(save2, async () => {
      try {
        await call("resetWithRecovery", { recoveryKey: rk.value, next: m2.pw.value });
        rk.value = m2.pw.value = m2.confirm.value = "";
        toast("Contraseña maestra restablecida.");
      } catch (e2) {
        if (!app.handleLocked(e2)) err2.show(errorText(codeOf(e2)));
      }
    }, "Restableciendo…");
  });
  return section("Contraseña maestra", form, h("details", null, h("summary", null, "¿No recuerdas la actual? Usa la clave de recuperación"), form2));
}

function recoverySection(app: App): HTMLElement {
  const current = labeledSecret("Contraseña maestra actual", { autocomplete: "current-password" });
  const err = errorBox();
  const go = h("button", { type: "submit", class: "btn small" }, "Generar nueva clave de recuperación");
  const form = h("form", { novalidate: true },
    h("p", { class: "hint" }, "La clave anterior dejará de funcionar en cuanto se guarde la bóveda (y en tus otros dispositivos al sincronizar)."),
    current.el, err.el, go);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    err.clear();
    if (!current.input.value) return err.show("Introduce la contraseña actual.");
    void busy(go, async () => {
      try {
        const { recoveryKey } = await call<{ recoveryKey: string }>("rotateRecovery", { current: current.input.value });
        current.input.value = "";
        app.nav.recoveryKey(recoveryKey, () => void app.nav.settings(), "Nueva clave de recuperación");
      } catch (e2) {
        if (!app.handleLocked(e2)) err.show(errorText(codeOf(e2)));
      }
    });
  });
  return section("Clave de recuperación", form);
}

function dataKeySection(app: App): HTMLElement {
  const current = labeledSecret("Contraseña maestra actual", { autocomplete: "current-password" });
  const err = errorBox();
  const go = h("button", { type: "submit", class: "btn small" }, "Rotar clave de cifrado");
  const form = h("form", { novalidate: true },
    h("p", { class: "hint" }, "Genera una clave de cifrado nueva para tus datos y una clave de recuperación nueva. Protege lo que guardes a partir de ahora si sospechas que alguien obtuvo tu clave anterior."),
    h("p", { class: "hint" }, "Las copias antiguas (exportaciones o versiones previas en Google Drive) siguen pudiéndose abrir con los secretos anteriores. Tus otros dispositivos te pedirán la contraseña maestra al sincronizar. Si Google Drive está conectado, se sincroniza antes de rotar (hace falta conexión)."),
    current.el, err.el, go);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    err.clear();
    if (!current.input.value) return err.show("Introduce la contraseña actual.");
    void busy(go, async () => {
      try {
        const { recoveryKey } = await call<{ recoveryKey: string }>("rotateDataKey", { current: current.input.value });
        current.input.value = "";
        app.nav.recoveryKey(recoveryKey, () => void app.nav.settings(), "Nueva clave de recuperación");
      } catch (e2) {
        if (!app.handleLocked(e2)) err.show(errorText(codeOf(e2)));
      }
    }, "Rotando…");
  });
  return section("Clave de cifrado", form);
}

function backupSection(app: App): HTMLElement {
  const exp = h("button", { type: "button", class: "btn small" }, "Exportar copia cifrada");
  exp.addEventListener("click", () => void busy(exp, async () => {
    try {
      const { fileName, container } = await call<{ fileName: string; container: string }>("export");
      downloadText(fileName, container);
      toast("Copia cifrada descargada. Necesitarás tu contraseña maestra para usarla.");
    } catch (e) {
      if (!app.handleLocked(e)) toast(errorText(codeOf(e)), "error");
    }
  }));
  const file = h("input", { type: "file", accept: ".json,application/json" });
  const err = errorBox();
  const imp = h("button", { type: "submit", class: "btn small" }, "Importar y fusionar");
  const form = h("form", { novalidate: true }, field("Importar copia de esta misma bóveda", file, "Se fusiona sin perder datos; las copias de otra bóveda se rechazan."), err.el, imp);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    err.clear();
    const f = file.files?.[0];
    if (!f) return err.show("Elige un archivo.");
    void busy(imp, async () => {
      try {
        const r = await call<{ added: number; updated: number; removed: number; newConflicts: number }>("import", { container: await f.text() });
        toast(`Copia fusionada: ${r.added} nuevas, ${r.updated} actualizadas, ${r.removed} eliminadas, ${r.newConflicts} conflictos.`);
        file.value = "";
      } catch (e2) {
        if (!app.handleLocked(e2)) err.show(errorText(codeOf(e2)));
      }
    }, "Importando…");
  });
  return section("Copia de seguridad", h("p", { class: "hint" }, "La copia está cifrada: es independiente de Google Drive y sirve para restaurar en otro navegador."), exp, form);
}

function syncSection(app: App, s: SyncStatusView): HTMLElement {
  if (!s.configured) {
    return section("Sincronización (Google Drive)", h("p", { class: "muted" }, "No configurado: esta compilación no incluye un ID de cliente OAuth de Google."));
  }
  const err = errorBox();
  const refresh = () => void app.nav.settings();
  if (!s.connected) {
    const connect = h("button", { type: "button", class: "btn small primary" }, "Conectar con Google Drive");
    connect.addEventListener("click", () => void busy(connect, async () => {
      err.clear();
      try {
        toast("Se abrirá una ventana de Google. Si este panel se cierra, vuelve a abrir Keyvora al terminar.");
        await call("sync.connect");
        toast("Google Drive conectado.");
        refresh();
      } catch (e) {
        if (!app.handleLocked(e)) err.show(errorText(codeOf(e)));
      }
    }, "Conectando…"));
    return section("Sincronización (Google Drive)",
      h("p", { class: "hint" }, "Solo se sube la bóveda cifrada a la carpeta oculta de Keyvora en tu Drive (permiso drive.appdata)."),
      connect, err.el);
  }
  const now = h("button", { type: "button", class: "btn small primary" }, "Sincronizar ahora");
  now.addEventListener("click", () => void busy(now, async () => {
    err.clear();
    try {
      await call("sync.now");
      toast("Sincronizado.");
      refresh();
    } catch (e) {
      if (!app.handleLocked(e)) err.show(errorText(codeOf(e)));
    }
  }, "Sincronizando…"));
  const disc = h("button", { type: "button", class: "btn small" }, "Desconectar");
  disc.addEventListener("click", async () => {
    const ok = await confirmDialog({ title: "¿Desconectar Google Drive?", body: [h("p", null, "Tus datos locales no se borran. La copia en Drive se conserva.")], confirm: "Desconectar" });
    if (!ok) return;
    try {
      await call("sync.disconnect");
      refresh();
    } catch (e) {
      err.show(errorText(codeOf(e)));
    }
  });
  const ack = h("button", { type: "button", class: "btn small" }, "Entendido");
  ack.addEventListener("click", () => void call("sync.status", { acknowledgeRollback: true }).then(refresh, () => undefined));
  return section("Sincronización (Google Drive)",
    h("dl", { class: "details compact" },
      h("div", { class: "kv" }, h("dt", null, "Estado"), h("dd", null, s.syncing ? "Sincronizando…" : "Conectado")),
      h("div", { class: "kv" }, h("dt", null, "Última sincronización"), h("dd", null, formatDate(s.lastSyncAt))),
      h("div", { class: "kv" }, h("dt", null, "Cambios pendientes"), h("dd", null, s.dirty ? "Sí" : "No")),
      s.lastError ? h("div", { class: "kv" }, h("dt", null, "Último error"), h("dd", { class: "error-text" }, errorText(s.lastError))) : null,
    ),
    s.rollbackWarning
      ? h("div", { class: "warning", role: "alert" }, "La versión de Google Drive es más antigua que una que ya se había visto (posible restauración o manipulación). Se ha fusionado sin perder datos locales. ", ack)
      : null,
    s.keysChanged ? keysChangedPanel(app, refresh) : null,
    s.lastMerge?.recoveryKeyChanged ? h("p", { class: "warning", role: "alert" }, RECOVERY_KEY_CHANGED_TEXT) : null,
    s.lastMerge?.kdfWeakened ? h("p", { class: "warning" }, KDF_WEAKENED_TEXT) : null,
    s.lastMerge?.keyringConflict ? h("p", { class: "warning" }, "Se cambiaron las claves en dos dispositivos a la vez; revisa que tu contraseña maestra actual funciona en ambos.") : null,
    h("div", { class: "row" }, now, disc),
    err.el,
  );
}

export async function renderSettings(app: App): Promise<void> {
  let minutes = 5;
  let sync: SyncStatusView;
  try {
    const [s, st] = await Promise.all([call<{ autoLockMinutes: number }>("settings.get"), call<SyncStatusView>("sync.status")]);
    await call("list"); // also verifies the session is unlocked
    minutes = s.autoLockMinutes;
    sync = st;
  } catch (e) {
    if (!app.handleLocked(e)) toast(errorText(codeOf(e)), "error");
    return;
  }
  app.show(
    topBar(app, "Ajustes", { back: () => void app.nav.list() }),
    h("main", { class: "content" },
      autoLockSection(app, minutes),
      syncSection(app, sync),
      masterSection(app),
      recoverySection(app),
      dataKeySection(app),
      backupSection(app),
    ),
  );
}
