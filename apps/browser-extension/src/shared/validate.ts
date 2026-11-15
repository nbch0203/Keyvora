// Small runtime validators for message payloads. They throw KvError("BAD_REQUEST") and never echo values.
import { KvError } from "./errors.ts";
import type { EntryInput, GeneratorOptions } from "../core/types.ts";

export type Obj = Record<string, unknown>;

export function obj(v: unknown): Obj {
  if (v === undefined || v === null) return {};
  if (typeof v !== "object" || Array.isArray(v)) throw new KvError("BAD_REQUEST");
  return v as Obj;
}

export function str(o: Obj, key: string, opts: { min?: number; max?: number; optional?: boolean } = {}): string {
  const v = o[key];
  if (v === undefined && opts.optional) return "";
  if (typeof v !== "string") throw new KvError("BAD_REQUEST");
  if (opts.min !== undefined && v.length < opts.min) throw new KvError("BAD_REQUEST");
  if (v.length > (opts.max ?? 65_536)) throw new KvError("BAD_REQUEST");
  return v;
}

export function bool(o: Obj, key: string): boolean {
  const v = o[key];
  if (v === undefined) return false;
  if (typeof v !== "boolean") throw new KvError("BAD_REQUEST");
  return v;
}

export function int(o: Obj, key: string, min: number, max: number): number {
  const v = o[key];
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) throw new KvError("BAD_REQUEST");
  return v;
}

/** Validates the structural shape of an EntryInput; field rules (lengths, URLs) are enforced by the core. */
export function entryInput(v: unknown): EntryInput {
  const o = obj(v);
  const urls = o["urls"] ?? [];
  if (!Array.isArray(urls) || urls.length > 16 || !urls.every((u) => typeof u === "string" && u.length <= 2048)) {
    throw new KvError("BAD_REQUEST");
  }
  return {
    title: str(o, "title", { max: 1024 }),
    username: str(o, "username", { max: 2048, optional: true }),
    password: str(o, "password", { max: 16_384, optional: true }),
    urls: (urls as string[]).map((u) => u.trim()).filter((u) => u.length > 0),
    notes: str(o, "notes", { max: 65_536, optional: true }),
  };
}

const GEN_BOOLS = ["lowercase", "uppercase", "digits", "symbols", "excludeAmbiguous", "requireEachClass"] as const;

export function generatorOptions(v: unknown): GeneratorOptions {
  const o = obj(v);
  const out: GeneratorOptions = {};
  for (const k of Object.keys(o)) {
    if (k !== "length" && !(GEN_BOOLS as readonly string[]).includes(k)) throw new KvError("BAD_REQUEST");
  }
  if (o["length"] !== undefined) out.length = int(o, "length", 8, 128);
  for (const k of GEN_BOOLS) if (o[k] !== undefined) out[k] = bool(o, k);
  return out;
}
