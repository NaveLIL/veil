export const PUBLIC_FAILURE_CODES_V1 = [
  "VEIL-SETUP-001",
  "VEIL-SETUP-002",
  "VEIL-LOCAL-001",
  "VEIL-LOCAL-002",
  "VEIL-LOCAL-003",
  "VEIL-NODE-001",
  "VEIL-NODE-002",
  "VEIL-NODE-003",
  "VEIL-NODE-004",
  "VEIL-PASS-001",
  "VEIL-PASS-002",
  "VEIL-PASS-003",
  "VEIL-RUNTIME-001",
  "VEIL-RUNTIME-002",
  "VEIL-SYNC-001",
  "VEIL-RUNTIME-999",
] as const;

export type PublicFailureCodeV1 = typeof PUBLIC_FAILURE_CODES_V1[number];

export interface PublicFailurePresentationV1 {
  code: PublicFailureCodeV1;
  title: string;
  description: string;
  nextAction: string;
}

export const UNKNOWN_PUBLIC_FAILURE_CODE_V1: PublicFailureCodeV1 = "VEIL-RUNTIME-999";

const PUBLIC_FAILURE_CODE_SET_V1 = new Set<string>(PUBLIC_FAILURE_CODES_V1);

const ENGLISH_PUBLIC_FAILURE_CATALOG_V1: Record<
  PublicFailureCodeV1,
  Omit<PublicFailurePresentationV1, "code">
> = {
  "VEIL-SETUP-001": {
    title: "Secure setup did not start",
    description: "Veil could not start the protected identity ceremony. No local account change was confirmed.",
    nextAction: "Close Veil, reopen it, and start protected setup again.",
  },
  "VEIL-SETUP-002": {
    title: "Secure setup state is unconfirmed",
    description: "The protected ceremony, its result, or local identity publication could not be confirmed.",
    nextAction: "Only after native reports the ceremony settled, use the vault check: destroy a new create phrase after confirmed absence; otherwise keep it and do not restart setup.",
  },
  "VEIL-LOCAL-001": {
    title: "Local account is locked",
    description: "The encrypted local account is not open or is still settling.",
    nextAction: "Open this same local account, then repeat the action.",
  },
  "VEIL-LOCAL-002": {
    title: "Encrypted local account is unavailable",
    description: "Veil could not open the protected vault and encrypted account database.",
    nextAction: "Close and reopen Veil. Do not create a new recovery phrase.",
  },
  "VEIL-LOCAL-003": {
    title: "Secure local state is unverified",
    description: "Veil could not confirm the native account boundary, so networking and messages remain closed.",
    nextAction: "Lock and reopen this same local account before continuing.",
  },
  "VEIL-NODE-001": {
    title: "Veil Node address is invalid",
    description: "The address is not one exact canonical HTTPS origin accepted by Veil.",
    nextAction: "Correct the Node address and try again without weakening TLS checks.",
  },
  "VEIL-NODE-002": {
    title: "Veil Node transport is unavailable",
    description: "A typed temporary network failure stopped the secure connection.",
    nextAction: "Check connectivity, then reconnect with this same local account.",
  },
  "VEIL-NODE-003": {
    title: "Veil Node authentication was rejected",
    description: "The Node did not authenticate this account. Veil does not expose a more specific pre-proof reason.",
    nextAction: "Retry with this same local account. Do not create a new recovery phrase.",
  },
  "VEIL-NODE-004": {
    title: "Veil Node security check failed",
    description: "TLS, protocol, authenticated binding, or connection-epoch verification did not pass.",
    nextAction: "Do not bypass certificate or trust checks. Verify the Node configuration before retrying.",
  },
  "VEIL-PASS-001": {
    title: "Node Access Pass is required",
    description: "After account-key proof, this Node reported that registration requires a valid mobile Access Pass.",
    nextAction: "Keep this local account and open a valid Pass issued for this Node.",
  },
  "VEIL-PASS-002": {
    title: "Node Access Pass was rejected",
    description: "After account-key proof, the Node reported that the Pass is invalid, expired, or already used.",
    nextAction: "Keep this local account and request a fresh Pass. Do not create a new recovery phrase.",
  },
  "VEIL-PASS-003": {
    title: "Pending Node Access Pass is unavailable",
    description: "The local pending Pass is missing, expired, changed, or cannot be read safely.",
    nextAction: "Keep this local account and open a fresh Pass only when Veil asks for one.",
  },
  "VEIL-RUNTIME-001": {
    title: "Secure operation is still finishing",
    description: "The previous native operation still owns the protected runtime boundary.",
    nextAction: "Wait a moment, then repeat the action.",
  },
  "VEIL-RUNTIME-002": {
    title: "Secure operation was cancelled",
    description: "Android lifecycle or an explicit lock cancelled the native operation.",
    nextAction: "Return to Veil and repeat the action with this same local account.",
  },
  "VEIL-SYNC-001": {
    title: "Secure Direct sync did not complete",
    description: "The account authenticated and remains saved, but native Direct bootstrap did not reach Ready.",
    nextAction: "Reconnect with this same account. Do not use a new Access Pass.",
  },
  "VEIL-RUNTIME-999": {
    title: "Secure operation could not be verified",
    description: "Veil received an unknown, malformed, or not-yet-reviewed outcome and failed closed.",
    nextAction: "Keep this local account, close and reopen Veil, and do not bypass security checks.",
  },
};

export function isPublicFailureCodeV1(value: unknown): value is PublicFailureCodeV1 {
  return typeof value === "string" && PUBLIC_FAILURE_CODE_SET_V1.has(value);
}

export function normalizePublicFailureCodeV1(value: unknown): PublicFailureCodeV1 {
  return isPublicFailureCodeV1(value) ? value : UNKNOWN_PUBLIC_FAILURE_CODE_V1;
}

/** Deterministic bundled English fallback. No remote or native text participates. */
export function publicFailurePresentationV1(
  value: unknown,
): PublicFailurePresentationV1 {
  const code = normalizePublicFailureCodeV1(value);
  return { code, ...ENGLISH_PUBLIC_FAILURE_CATALOG_V1[code] };
}
