// Types for scripts/manifest.mjs (used by unit tests).
export type Manifest = Record<string, any>;
export const REQUIRED_PERMISSIONS: string[];
export const FORBIDDEN_KEYS: string[];
export const FIREFOX_ID: string;
export const E2E_HOSTS: string[];
export const CHROMIUM_PUBLIC_KEY: string;
export const CHROMIUM_EXTENSION_ID: string;
export function assertBaseManifest(m: Manifest): void;
export function chromiumManifest(base: Manifest, opts?: { store?: boolean }): Manifest;
export function firefoxManifest(base: Manifest): Manifest;
export function e2eManifest(base: Manifest): Manifest;
