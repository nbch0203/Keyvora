// Functions injected with chrome.scripting.executeScript into the top frame of the active tab (ADR-009).
// They MUST be self-contained (they are serialized with Function.prototype.toString): no imports, no references to
// module-level identifiers; helpers are declared inside. They receive only {expectedOrigin, username, password},
// abort unless they run in the top frame of the expected origin, touch only visible and enabled inputs, and return
// a status code (never data from the page).

export type FillResult = "filled" | "no-form" | "ambiguous" | "origin-mismatch";

export interface FillArgs {
  expectedOrigin: string;
  username: string;
  password: string;
}

export const FILL_RESULTS: readonly FillResult[] = ["filled", "no-form", "ambiguous", "origin-mismatch"];

/** Login: exactly one visible password field; username = nearest preceding visible text/email/tel in the same form. */
export function fillLoginInPage(args: FillArgs): FillResult {
  if (typeof location === "undefined" || location.origin !== args.expectedOrigin || window.top !== window) {
    return "origin-mismatch";
  }
  const usable = (el: HTMLInputElement): boolean => {
    if (el.disabled || el.readOnly) return false;
    const cv = (el as { checkVisibility?: (o: object) => boolean }).checkVisibility;
    if (typeof cv === "function" && !cv.call(el, { checkOpacity: true, checkVisibilityCSS: true })) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    if (r.right + window.scrollX <= 0 || r.bottom + window.scrollY <= 0) return false;
    const s = window.getComputedStyle(el);
    return s.visibility !== "hidden" && s.display !== "none" && Number(s.opacity || "1") > 0.05;
  };
  const setValue = (el: HTMLInputElement, value: string): void => {
    const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const inputs = Array.from(document.querySelectorAll("input"));
  const passwords = inputs.filter((el) => el.type === "password" && usable(el));
  if (passwords.length === 0) return "no-form";
  if (passwords.length > 1) return "ambiguous";
  const pw = passwords[0]!;
  if (args.username) {
    let user: HTMLInputElement | null = null;
    for (const el of inputs) {
      if (el === pw) break; // document order: everything before is "preceding"
      if ((el.type === "text" || el.type === "email" || el.type === "tel") && el.form === pw.form && usable(el)) user = el;
    }
    if (user) setValue(user, args.username);
  }
  setValue(pw, args.password);
  return "filled";
}

/**
 * Registration / new password: fills every visible password field of a single form (new + confirmation), at most
 * two; more fields (e.g. "current password" forms) or fields spread over several forms → "ambiguous".
 */
export function fillNewPasswordInPage(args: FillArgs): FillResult {
  if (typeof location === "undefined" || location.origin !== args.expectedOrigin || window.top !== window) {
    return "origin-mismatch";
  }
  const usable = (el: HTMLInputElement): boolean => {
    if (el.disabled || el.readOnly) return false;
    const cv = (el as { checkVisibility?: (o: object) => boolean }).checkVisibility;
    if (typeof cv === "function" && !cv.call(el, { checkOpacity: true, checkVisibilityCSS: true })) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    if (r.right + window.scrollX <= 0 || r.bottom + window.scrollY <= 0) return false;
    const s = window.getComputedStyle(el);
    return s.visibility !== "hidden" && s.display !== "none" && Number(s.opacity || "1") > 0.05;
  };
  const setValue = (el: HTMLInputElement, value: string): void => {
    const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const inputs = Array.from(document.querySelectorAll("input"));
  const passwords = inputs.filter((el) => el.type === "password" && usable(el));
  if (passwords.length === 0) return "no-form";
  const form = passwords[0]!.form;
  if (passwords.length > 2 || passwords.some((p) => p.form !== form)) return "ambiguous";
  if (args.username) {
    let user: HTMLInputElement | null = null;
    for (const el of inputs) {
      if (el === passwords[0]) break;
      if ((el.type === "text" || el.type === "email" || el.type === "tel") && el.form === form && usable(el)) user = el;
    }
    if (user && user.value === "") setValue(user, args.username);
  }
  for (const p of passwords) setValue(p, args.password);
  return "filled";
}
