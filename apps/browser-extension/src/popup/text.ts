// User-facing texts (Spanish). Error codes are mapped here; raw codes are never shown alone.

const ERRORS: Record<string, string> = {
  INVALID_CREDENTIALS: "Contraseña o clave incorrecta.",
  INVALID_RECOVERY_KEY: "La clave de recuperación no es válida. Revisa que esté bien escrita.",
  LOCKED: "La bóveda está bloqueada.",
  VALIDATION: "Hay datos no válidos. Revisa los campos (el título es obligatorio y las URLs deben ser válidas).",
  VAULT_MISMATCH: "La copia pertenece a otra bóveda; no se ha importado.",
  KEYRING_CHANGED: "La contraseña maestra o la clave de cifrado cambió en otro dispositivo. Introduce la contraseña maestra actual para seguir sincronizando.",
  INTEGRITY_ERROR: "Los datos están dañados o han sido manipulados. No se ha cambiado nada.",
  INVALID_FORMAT: "El archivo no tiene un formato de bóveda válido.",
  UNSUPPORTED_VERSION: "La bóveda usa una versión que esta extensión no admite.",
  PARAMS_OUT_OF_BOUNDS: "Los parámetros de cifrado están fuera de los límites permitidos.",
  NOT_FOUND: "La entrada ya no existe.",
  CRYPTO: "Error criptográfico interno.",
  BAD_REQUEST: "Petición no válida.",
  VAULT_EXISTS: "Ya existe una bóveda en este navegador.",
  NO_VAULT: "No hay ninguna bóveda en este navegador.",
  CORE_UNAVAILABLE: "No se pudo cargar el núcleo criptográfico de la extensión.",
  NO_ACTIVE_TAB: "No hay ninguna pestaña activa accesible.",
  NOT_FILLABLE: "Esta página no admite autorrelleno (solo páginas HTTPS).",
  NO_MATCH: "Esta entrada no corresponde a la página actual; no se ha rellenado.",
  CONFIRMATION_REQUIRED: "Hace falta confirmar el dominio antes de rellenar.",
  INJECTION_FAILED: "No se pudo acceder a la página para rellenarla.",
  SYNC_NOT_CONFIGURED: "La sincronización no está configurada en esta compilación.",
  SYNC_NOT_CONNECTED: "La sincronización no está conectada.",
  REMOTE_EMPTY: "No hay ninguna bóveda en tu Google Drive. Crea una nueva y se subirá automáticamente.",
  CONFLICT_RETRY_EXHAUSTED: "Hubo demasiados cambios simultáneos; tus datos siguen a salvo aquí y se reintentará más tarde.",
  NETWORK: "No se pudo contactar con Google Drive. Se reintentará más tarde.",
  AUTH_REQUIRED: "Hay que volver a conectar con Google Drive.",
  RATE_LIMITED: "Google Drive está limitando las peticiones. Se reintentará más tarde.",
  REMOTE_ERROR: "Google Drive devolvió un error.",
  UNKNOWN: "Ha ocurrido un error inesperado.",
};

export function errorText(code: string): string {
  return ERRORS[code] ?? ERRORS["UNKNOWN"]!;
}

export const KDF_WEAKENED_TEXT =
  "Aviso: la contraseña maestra adoptada usa parámetros de protección más débiles de lo recomendado. Cámbiala en Ajustes → Contraseña maestra para reforzarla.";

export const FILL_TEXT: Record<string, string> = {
  filled: "Formulario rellenado.",
  "no-form": "No se encontró un formulario de inicio de sesión visible en la página.",
  ambiguous: "La página tiene varios campos de contraseña; por seguridad no se ha rellenado.",
  "origin-mismatch": "La página cambió de dirección; por seguridad no se ha rellenado.",
};

export function entropyLabel(bits: number): string {
  if (bits < 50) return "débil";
  if (bits < 80) return "aceptable";
  if (bits < 110) return "fuerte";
  return "muy fuerte";
}

export function formatDate(iso: string | number | null | undefined): string {
  if (iso === null || iso === undefined || iso === "") return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString("es-ES", { dateStyle: "medium", timeStyle: "short" });
}

/** QA-DEF-004: the adopted keys carry another recovery key. */
export const RECOVERY_KEY_CHANGED_TEXT =
  "La clave de recuperación que se mostró en este dispositivo ya no es válida: ahora vale la generada en el otro dispositivo. " +
  "Si no la tienes guardada, ve a Ajustes → «Generar nueva clave de recuperación» y guarda la nueva.";
