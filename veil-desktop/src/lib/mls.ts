// Phase 6 — OpenMLS facade for the renderer.
//
// All MLS operations route through Tauri commands defined in
// `src-tauri/src/mls_cmd.rs`. The renderer never sees raw MLS bytes:
// blobs are base64 strings and group IDs are hex.
//
// Naming convention: `mls_*` for native commands, exported as
// camelCase functions here. These helpers are intentionally dumb —
// higher-level orchestration (publish KP → REST, fetch welcomes,
// pump commits) lives in `stores/app.ts` so it can share the existing
// signed-request plumbing.

import { invoke } from "@tauri-apps/api/core";

/** Initialise the local MLS client for this session. Returns the
 *  hex-encoded Ed25519 public signature key. */
export function mlsInit(leafIdentityHex: string): Promise<string> {
  return invoke<string>("mls_init", { leafIdentityHex });
}

export function mlsReady(): Promise<boolean> {
  return invoke<boolean>("mls_ready");
}

/** Generate `count` fresh KeyPackages (base64). Caller publishes via
 *  POST /v1/mls/keypackages. Recommended pool size: 20–30. */
export function mlsGenerateKeyPackages(count: number): Promise<string[]> {
  return invoke<string[]>("mls_generate_key_packages", { count });
}

/** Create a new MLS group keyed by the conversation UUID (hex). */
export function mlsCreateGroup(groupIdHex: string): Promise<number> {
  return invoke<number>("mls_create_group", { groupIdHex });
}

export type AddMemberResult = {
  commit_b64: string;
  welcome_b64: string;
  epoch: number;
};

/** Add a member by consuming their KeyPackage. Caller must publish the
 *  returned commit (POST /v1/mls/commits) and welcome
 *  (POST /v1/mls/welcomes). */
export function mlsAddMember(
  groupIdHex: string,
  keyPackageB64: string,
): Promise<AddMemberResult> {
  return invoke<AddMemberResult>("mls_add_member", {
    groupIdHex,
    keyPackageB64,
  });
}

/** Process a Welcome we pulled from GET /v1/mls/welcomes. Returns the
 *  joined group's hex ID. */
export function mlsProcessWelcome(welcomeB64: string): Promise<string> {
  return invoke<string>("mls_process_welcome", { welcomeB64 });
}

/** Apply a commit pulled from GET /v1/mls/commits/{conv}?after_epoch=N.
 *  Returns the new local epoch. */
export function mlsProcessCommit(
  groupIdHex: string,
  commitB64: string,
): Promise<number> {
  return invoke<number>("mls_process_commit", { groupIdHex, commitB64 });
}

export function mlsEncrypt(groupIdHex: string, plaintext: string): Promise<string> {
  return invoke<string>("mls_encrypt", { groupIdHex, plaintext });
}

export function mlsDecrypt(groupIdHex: string, ciphertextB64: string): Promise<string> {
  return invoke<string>("mls_decrypt", { groupIdHex, ciphertextB64 });
}

export function mlsEpoch(groupIdHex: string): Promise<number> {
  return invoke<number>("mls_epoch", { groupIdHex });
}

export function mlsExportSecret(
  groupIdHex: string,
  contextB64: string,
  length: number,
): Promise<string> {
  return invoke<string>("mls_export_secret", { groupIdHex, contextB64, length });
}
