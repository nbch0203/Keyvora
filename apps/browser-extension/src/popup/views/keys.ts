// "Keys changed on another device" prompt (ADR-013): remote keys are never adopted silently; the user proves it was
// them by typing the master password that is valid for the remote vault.
import { call, codeOf } from "../api.ts";
import type { App } from "../app.ts";
import { busy, errorBox, h, labeledSecret, toast } from "../dom.ts";
import { errorText, KDF_WEAKENED_TEXT, RECOVERY_KEY_CHANGED_TEXT } from "../text.ts";

export function keysChangedPanel(app: App, onDone: () => void): HTMLElement {
  const pw = labeledSecret("Contraseña maestra actual (la establecida en el otro dispositivo)", { autocomplete: "current-password", id: "adopt-password" });
  const err = errorBox();
  const go = h("button", { type: "submit", class: "btn small primary" }, "Continuar");
  const form = h("form", { novalidate: true, class: "warning keys-changed", role: "alert" },
    h("strong", null, "La contraseña maestra o la clave de cifrado cambió en otro dispositivo."),
    h("p", null, "La sincronización está en pausa. Introduce la contraseña maestra vigente para aceptar el cambio; tus datos locales se conservan y se fusionan."),
    pw.el, err.el, go);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    err.clear();
    if (!pw.input.value) return err.show("Introduce la contraseña maestra.");
    void busy(go, async () => {
      try {
        const r = await call<{ kdfWeakened: boolean; recoveryKeyChanged: boolean }>("sync.adoptRemoteKeys", { master: pw.input.value });
        pw.input.value = "";
        if (r.recoveryKeyChanged) toast(RECOVERY_KEY_CHANGED_TEXT, "error");
        else if (r.kdfWeakened) toast(KDF_WEAKENED_TEXT, "error");
        else toast("Cambio aceptado; la sincronización continúa.");
        onDone();
      } catch (e2) {
        if (!app.handleLocked(e2)) err.show(errorText(codeOf(e2)));
      }
    }, "Comprobando…");
  });
  return form;
}
