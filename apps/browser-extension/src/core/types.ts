// Single entry point for the core contract types (packages/shared-models/ts/types.ts, contract v1).
// The extension never redefines these shapes.
export type {
  ErrorCode,
  KdfParams,
  EntryInput,
  EntrySummary,
  HistoryItem,
  ConflictSnapshot,
  Entry,
  MatchLevel,
  CredentialMatch,
  MergeReport,
  GeneratorOptions,
  CoreVault,
  CoreModule,
} from "../../../../packages/shared-models/ts/types.ts";
export { errorCode } from "../../../../packages/shared-models/ts/types.ts";
