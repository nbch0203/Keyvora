// Types for scripts/manifest.mjs (used by unit tests).
export type Manifest = Record<string, any>;
export const REQUIRED_PERMISSIONS: string[];
export const FORBIDDEN_KEYS: string[];
export const FIREFOX_ID: string;
export const E2E_HOSTS: string[];
export function assertBaseManifest(m: Manifest): void;
export function chromiumManifest(base: Manifest): Manifest;
export function firefoxManifest(base: Manifest): Manifest;
export function e2eManifest(base: Manifest): Manifest;
