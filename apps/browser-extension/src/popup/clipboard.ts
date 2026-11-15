// Clipboard with automatic clearing after 30 s (only possible while the popup stays open: an extension page
// cannot touch the clipboard after it is closed — documented limitation, THREAT_MODEL T18).
import { toast } from "./dom.ts";

export const CLIPBOARD_CLEAR_MS = 30_000;
let clearTimer: ReturnType<typeof setTimeout> | null = null;

export async function copySecret(value: string, what: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    toast("No se pudo copiar al portapapeles.", "error");
    return;
  }
  toast(`${what} copiado. Se borrará del portapapeles en 30 s (si Keyvora sigue abierto).`);
  if (clearTimer) clearTimeout(clearTimer);
  clearTimer = setTimeout(() => {
    clearTimer = null;
    navigator.clipboard.writeText("").catch(() => undefined);
  }, CLIPBOARD_CLEAR_MS);
}
