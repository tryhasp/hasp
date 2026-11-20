export { startAutofillContentScript, startPasskeyBridgeForWindow } from './content.ts';
export type { ContentScriptOptions } from './content.ts';
export type { ContentBackground, Engine, EngineNotice, HandoffStore } from './engine.ts';
export { installPasskeyHook } from './passkey/hook.ts';
export { createContentBackground, createFrameBackground } from './background-client.ts';
export type { Transport } from './background-client.ts';
export { mountMenuFrame } from './menu/menu-frame.ts';
export type { FrameBackground, FrameDeps } from './menu/menu-frame.ts';
export { collectHandovers } from './platform/frame-channel.ts';
export {
  attestationSchema,
  backgroundPushSchema,
  contentRequestSchema,
  frameReplySchemas,
  frameRequestSchema,
  replySchemas,
} from './protocol.ts';
export type {
  Attestation,
  BackgroundPush,
  Candidate,
  ContentKind,
  ContentRequest,
  FillReply,
  FrameHelloReply,
  FrameReplyOf,
  FrameRequest,
  MenuOpenReply,
  ProtocolError,
  ReplyOf,
} from './protocol.ts';
export { consumeGestureToken, mintGestureToken, GESTURE_TOKEN_TTL_MS } from './policy/gesture.ts';
export { verifyFillRequest } from './policy/fill-gate.ts';
export {
  capturePending,
  clearOnLock,
  clearPending,
  listGenerated,
  markGeneratedSaved,
  markGeneratedUnverified,
  markSubmitted,
  readPending,
  submittedPassword,
  recordGenerated,
  unsavedSignups,
} from './save/pending-store.ts';
export { decideSaveKind } from './save/decide.ts';
export {
  pageConfigFor,
  pageConfigSchema,
  siteEntrySchema,
  siteFileSchema,
} from './sites/site-rule.ts';
export type { PageConfig, SiteEntry } from './sites/site-rule.ts';
export { classifyPage } from './classify/classify.ts';
export type { SessionStore } from './ports.ts';
export type { Result } from './result.ts';
export { err, ok } from './result.ts';
export type { FormClass, FormKind, FieldPurpose, FrameKind } from './types.ts';
