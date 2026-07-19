import { create } from "zustand";

import type { PublicFailureCodeV1 } from "../contracts/publicFailureCodesV1";
import {
  beginNativeIdentitySetup,
  isNativeIdentitySetupStartError,
  type NativeIdentitySetupMode,
  type NativeIdentitySetupResult,
} from "../native/identitySetup";

export type IdentityVerificationResult = "present" | "absent" | "unknown";

interface IdentitySetupState {
  activeMode: NativeIdentitySetupMode | null;
  publicFailureCode: PublicFailureCodeV1 | null;
  recoveryNotice: string | null;
  restartBlocked: boolean;
}

type VerifiableSetupOutcome = Exclude<NativeIdentitySetupResult, "user_cancelled">
  | "ambiguous_start";

interface ActiveSetupAttempt {
  id: number;
  mode: NativeIdentitySetupMode;
  outcome: VerifiableSetupOutcome | null;
  verificationToken: number | null;
  verificationContinuationId: number | null;
}

interface IdentitySetupContinuation {
  /**
   * Returns the current verified runtime epoch, or null while privacy/boot
   * prevents an authoritative vault read.
   */
  getAuthorityEpoch: () => number | null;
  verifyIdentity: () => Promise<IdentityVerificationResult>;
  onIdentityPresent: () => Promise<void> | void;
}

interface RegisteredContinuation extends IdentitySetupContinuation {
  id: number;
}

const PUBLIC_REFRESH_RECOVERY =
  "Native setup reported completion, but Veil could not verify the encrypted local account. Keep the recovery phrase, close and reopen Veil, and do not start setup again yet.";
const PUBLIC_CREATE_CANCELLED =
  "Setup was cancelled. If a new recovery phrase was shown, it was not committed and must be destroyed before trying again.";
const PUBLIC_CREATE_INTERRUPTION_ABSENT =
  "Secure setup was interrupted and Veil verified that no local identity was committed. Any new recovery phrase from that attempt is invalid and must be destroyed before starting again.";
const PUBLIC_RESTORE_INTERRUPTION_ABSENT =
  "Secure restore was interrupted and Veil verified that no local identity was committed. Keep your existing recovery phrase and reopen Veil before trying again.";
const PUBLIC_INTERRUPTION_UNKNOWN =
  "Secure setup was interrupted, but Veil could not verify whether the local identity was committed. Keep any recovery phrase, close and reopen Veil, and do not start setup again until the local account check finishes.";
const PUBLIC_AMBIGUOUS_CREATE_START =
  "Protected setup may already be in progress or its result could not be matched. Even if the local vault is currently absent, keep any new recovery phrase, close and reopen Veil, and do not start setup again until the native ceremony is settled.";
const PUBLIC_AMBIGUOUS_RESTORE_START =
  "Protected restore may already be in progress or its result could not be matched. Keep your existing recovery phrase, close and reopen Veil, and do not start setup again until the native ceremony is settled.";

const initialIdentitySetupState: IdentitySetupState = {
  activeMode: null,
  publicFailureCode: null,
  recoveryNotice: null,
  restartBlocked: false,
};

/**
 * Process-local, non-secret receipt for the currently launched ceremony.
 *
 * This deliberately survives React screen/App remounts, but it is not a
 * durable Android process-death receipt. Native durable reconciliation remains
 * required before process-death setup recovery can be claimed.
 */
export const useIdentitySetupStore = create<IdentitySetupState>(() => ({
  ...initialIdentitySetupState,
}));

let nextAttemptId = 1;
let nextContinuationId = 1;
let nextVerificationToken = 1;
let activeAttempt: ActiveSetupAttempt | null = null;
let registeredContinuation: RegisteredContinuation | null = null;
let presentationAttemptId = 0;

export function beginIdentitySetup(mode: NativeIdentitySetupMode): void {
  const presentation = useIdentitySetupStore.getState();
  if (activeAttempt || presentation.restartBlocked) return;

  const attempt: ActiveSetupAttempt = {
    id: nextAttemptId++,
    mode,
    outcome: null,
    verificationToken: null,
    verificationContinuationId: null,
  };
  activeAttempt = attempt;
  presentationAttemptId = attempt.id;
  useIdentitySetupStore.setState({
    activeMode: mode,
    publicFailureCode: null,
    recoveryNotice: null,
    restartBlocked: false,
  });

  void beginNativeIdentitySetup(mode).then(
    (result) => acceptNativeResult(attempt.id, result),
    (error: unknown) => acceptNativeStartFailure(attempt.id, error),
  );
}

/** Register the App-owned continuation that remains alive while onboarding is hidden. */
export function registerIdentitySetupContinuation(
  continuation: IdentitySetupContinuation,
): () => void {
  const registration: RegisteredContinuation = {
    ...continuation,
    id: nextContinuationId++,
  };
  invalidateVerificationOwnedBy(registeredContinuation?.id ?? null);
  registeredContinuation = registration;
  resumeIdentitySetupContinuation();

  return () => {
    if (registeredContinuation !== registration) return;
    registeredContinuation = null;
    invalidateVerificationOwnedBy(registration.id);
  };
}

/** Retry a deferred result after the runtime publishes a new foreground epoch. */
export function resumeIdentitySetupContinuation(): void {
  const attempt = activeAttempt;
  const continuation = registeredContinuation;
  if (!attempt?.outcome || attempt.verificationToken !== null || !continuation) return;

  const authorityEpoch = continuation.getAuthorityEpoch();
  if (authorityEpoch === null) return;

  const token = nextVerificationToken++;
  attempt.verificationToken = token;
  attempt.verificationContinuationId = continuation.id;
  void Promise.resolve()
    .then(() => continuation.verifyIdentity())
    .then(
      (verification) => finishVerification(
        attempt.id,
        continuation,
        authorityEpoch,
        token,
        normalizeVerification(verification),
      ),
      () => finishVerification(
        attempt.id,
        continuation,
        authorityEpoch,
        token,
        "unknown",
      ),
    );
}

function acceptNativeResult(attemptId: number, result: NativeIdentitySetupResult): void {
  const attempt = activeAttempt;
  if (!attempt || attempt.id !== attemptId) return;

  if (result === "user_cancelled") {
    activeAttempt = null;
    useIdentitySetupStore.setState({
      activeMode: null,
      publicFailureCode: null,
      recoveryNotice: attempt.mode === "create" ? PUBLIC_CREATE_CANCELLED : null,
      restartBlocked: false,
    });
    return;
  }

  attempt.outcome = result;
  resumeIdentitySetupContinuation();
}

function acceptNativeStartFailure(attemptId: number, error: unknown): void {
  const attempt = activeAttempt;
  if (!attempt || attempt.id !== attemptId) return;

  if (isNativeIdentitySetupStartError(error) && error.kind === "unavailable") {
    activeAttempt = null;
    useIdentitySetupStore.setState({
      activeMode: null,
      publicFailureCode: "VEIL-SETUP-001",
      recoveryNotice: null,
      restartBlocked: false,
    });
    return;
  }

  // Busy and unknown failures may refer to an existing lease/ceremony. They
  // must take the strict verification path and can never claim no state change.
  attempt.outcome = "ambiguous_start";
  resumeIdentitySetupContinuation();
}

function finishVerification(
  attemptId: number,
  continuation: RegisteredContinuation,
  authorityEpoch: number,
  token: number,
  verification: IdentityVerificationResult,
): void {
  const attempt = activeAttempt;
  if (
    !attempt
    || attempt.id !== attemptId
    || attempt.verificationToken !== token
    || registeredContinuation !== continuation
  ) {
    return;
  }

  attempt.verificationToken = null;
  attempt.verificationContinuationId = null;
  if (continuation.getAuthorityEpoch() !== authorityEpoch) {
    // The vault result crossed a privacy/foreground epoch. Keep the native
    // outcome pending and retry only under fresh App-owned authority.
    resumeIdentitySetupContinuation();
    return;
  }

  if (verification === "present") {
    activeAttempt = null;
    useIdentitySetupStore.setState({
      activeMode: null,
      publicFailureCode: null,
      recoveryNotice: null,
      restartBlocked: false,
    });
    try {
      void Promise.resolve(continuation.onIdentityPresent()).catch(() => {
        failPresentRefresh(attemptId);
      });
    } catch {
      failPresentRefresh(attemptId);
    }
    return;
  }

  if (attempt.outcome === "ambiguous_start") {
    activeAttempt = null;
    useIdentitySetupStore.setState({
      activeMode: null,
      publicFailureCode: "VEIL-SETUP-002",
      recoveryNotice: attempt.mode === "create"
        ? PUBLIC_AMBIGUOUS_CREATE_START
        : PUBLIC_AMBIGUOUS_RESTORE_START,
      restartBlocked: true,
    });
    return;
  }

  if (attempt.outcome === "interrupted") {
    activeAttempt = null;
    useIdentitySetupStore.setState({
      activeMode: null,
      publicFailureCode: "VEIL-SETUP-002",
      recoveryNotice: verification === "absent"
        ? attempt.mode === "create"
          ? PUBLIC_CREATE_INTERRUPTION_ABSENT
          : PUBLIC_RESTORE_INTERRUPTION_ABSENT
        : PUBLIC_INTERRUPTION_UNKNOWN,
      restartBlocked: verification === "unknown"
        || (verification === "absent" && attempt.mode === "restore"),
    });
    return;
  }

  activeAttempt = null;
  useIdentitySetupStore.setState({
    activeMode: null,
    publicFailureCode: "VEIL-SETUP-002",
    recoveryNotice: PUBLIC_REFRESH_RECOVERY,
    restartBlocked: true,
  });
}

function failPresentRefresh(attemptId: number): void {
  // Do not overwrite a newer attempt/result if the App callback fails late.
  if (activeAttempt || presentationAttemptId !== attemptId) return;
  useIdentitySetupStore.setState({
    activeMode: null,
    publicFailureCode: "VEIL-SETUP-002",
    recoveryNotice: PUBLIC_REFRESH_RECOVERY,
    restartBlocked: true,
  });
}

function invalidateVerificationOwnedBy(continuationId: number | null): void {
  const attempt = activeAttempt;
  if (!attempt || continuationId === null || attempt.verificationToken === null) return;
  if (attempt.verificationContinuationId !== continuationId) return;
  // Tokens are unique and a registration owns at most one in-flight read. A
  // replaced App continuation must not be able to settle the pending result.
  attempt.verificationToken = null;
  attempt.verificationContinuationId = null;
}

function normalizeVerification(result: unknown): IdentityVerificationResult {
  return result === "present" || result === "absent" ? result : "unknown";
}

export function resetIdentitySetupStoreForTests(): void {
  activeAttempt = null;
  registeredContinuation = null;
  presentationAttemptId = 0;
  // Never allow a late Promise from a previous test/attempt to correlate with
  // newly allocated process-local identifiers.
  nextAttemptId += 1;
  nextContinuationId += 1;
  nextVerificationToken += 1;
  useIdentitySetupStore.setState(initialIdentitySetupState, true);
}
