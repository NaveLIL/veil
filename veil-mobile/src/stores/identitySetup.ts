import { create } from "zustand";

import type { PublicFailureCodeV1 } from "../contracts/publicFailureCodesV1";
import {
  beginNativeIdentitySetup,
  isNativeIdentitySetupStartError,
  reconcileNativeIdentitySetup,
  type NativeIdentitySetupMode,
  type NativeIdentitySetupReconciliationResult,
  type NativeIdentitySetupResult,
} from "../native/identitySetup";

export type IdentityVerificationResult = "present" | "absent" | "unknown";
export type NativeIdentityReconciliationGate = "checking" | "ready" | "blocked";

interface IdentitySetupState {
  activeMode: NativeIdentitySetupMode | null;
  nativeReconciliation: NativeIdentityReconciliationGate;
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
  /** Foreground epoch for native journal reads, which may precede runtime Ready. */
  getDurableReconciliationAuthorityEpoch?: () => number | null;
  verifyIdentity: () => Promise<IdentityVerificationResult>;
  onIdentityPresent: (
    expectedDurableAuthorityEpoch?: number,
  ) => Promise<"confirmed" | "superseded"> | "confirmed" | "superseded";
  /** Only the App-owned foreground authority may open the durable cold-start gate. */
  enableDurableReconciliation?: boolean;
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
const PUBLIC_DURABLE_RESTORE_INTERRUPTION_ABSENT =
  "Secure restore was interrupted and Veil verified that no local identity was committed. Keep your existing recovery phrase; you can try restore again.";
const PUBLIC_INTERRUPTION_UNKNOWN =
  "Secure setup was interrupted, but Veil could not verify whether the local identity was committed. Keep any recovery phrase, close and reopen Veil, and do not start setup again until the local account check finishes.";
const PUBLIC_AMBIGUOUS_CREATE_START =
  "Protected setup may already be in progress or its result could not be matched. Even if the local vault is currently absent, keep any new recovery phrase, close and reopen Veil, and do not start setup again until the native ceremony is settled.";
const PUBLIC_AMBIGUOUS_RESTORE_START =
  "Protected restore may already be in progress or its result could not be matched. Keep your existing recovery phrase, close and reopen Veil, and do not start setup again until the native ceremony is settled.";

const initialIdentitySetupState: IdentitySetupState = {
  activeMode: null,
  nativeReconciliation: "checking",
  publicFailureCode: null,
  recoveryNotice: null,
  restartBlocked: false,
};

/**
 * Process-local, non-secret receipt for the currently launched ceremony.
 *
 * This deliberately survives React screen/App remounts, but it is not a
 * durable Android process-death receipt. The App route separately reconciles
 * the retained native journal; JavaScript only deduplicates its at-least-once
 * terminal delivery within this process.
 */
export const useIdentitySetupStore = create<IdentitySetupState>(() => ({
  ...initialIdentitySetupState,
}));

let nextAttemptId = 1;
let nextContinuationId = 1;
let nextVerificationToken = 1;
let nextReconciliationToken = 1;
let activeAttempt: ActiveSetupAttempt | null = null;
let registeredContinuation: RegisteredContinuation | null = null;
let presentationAttemptId = 0;
let activeReconciliation: {
  token: number;
  continuationId: number;
  authorityEpoch: number;
} | null = null;
const handledTerminalReceipts = new Map<string, NativeIdentitySetupResult>();

export function beginIdentitySetup(mode: NativeIdentitySetupMode): void {
  const presentation = useIdentitySetupStore.getState();
  if (
    activeAttempt ||
    presentation.restartBlocked ||
    presentation.nativeReconciliation !== "ready"
  ) return;

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
  invalidateReconciliationOwnedBy(registeredContinuation?.id ?? null);
  registeredContinuation = registration;
  if (registration.enableDurableReconciliation) {
    useIdentitySetupStore.setState({ nativeReconciliation: "checking" });
  }
  resumeIdentitySetupContinuation();

  return () => {
    if (registeredContinuation !== registration) return;
    registeredContinuation = null;
    invalidateVerificationOwnedBy(registration.id);
    invalidateReconciliationOwnedBy(registration.id);
    if (registration.enableDurableReconciliation) {
      // Zustand survives a React root reload. Close the route synchronously so
      // a remounted App cannot render onboarding before a fresh native read.
      useIdentitySetupStore.setState({ nativeReconciliation: "checking" });
    }
  };
}

/** Retry a deferred result after the runtime publishes a new foreground epoch. */
export function resumeIdentitySetupContinuation(): void {
  resumeLiveIdentitySetupContinuation();
  resumeDurableIdentitySetupReconciliation();
}

/** Explicit user retry after a fail-closed durable reconciliation outcome. */
export function retryIdentitySetupReconciliation(): void {
  const continuation = registeredContinuation;
  if (!continuation?.enableDurableReconciliation) return;
  if (activeReconciliation !== null) return;
  useIdentitySetupStore.setState({ nativeReconciliation: "checking" });
  resumeDurableIdentitySetupReconciliation();
}

function resumeLiveIdentitySetupContinuation(): void {
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

function resumeDurableIdentitySetupReconciliation(): void {
  const continuation = registeredContinuation;
  if (
    !continuation?.enableDurableReconciliation
    || activeReconciliation !== null
    || useIdentitySetupStore.getState().nativeReconciliation !== "checking"
  ) return;

  const authorityEpoch = getDurableReconciliationAuthorityEpoch(continuation);
  if (authorityEpoch === null) return;

  const token = nextReconciliationToken++;
  activeReconciliation = {
    token,
    continuationId: continuation.id,
    authorityEpoch,
  };
  void reconcileNativeIdentitySetup().then(
    (result) => finishDurableReconciliation(
      continuation,
      authorityEpoch,
      token,
      result,
    ),
    // The native bridge already sanitizes rejections, but retain fail-closed
    // behavior if a test double or future wrapper violates that contract.
    () => finishDurableReconciliation(
      continuation,
      authorityEpoch,
      token,
      { status: "unconfirmed" },
    ),
  );
}

function finishDurableReconciliation(
  continuation: RegisteredContinuation,
  authorityEpoch: number,
  token: number,
  result: NativeIdentitySetupReconciliationResult,
): void {
  if (!ownsActiveReconciliation(continuation, token)) return;

  if (getDurableReconciliationAuthorityEpoch(continuation) !== authorityEpoch) {
    activeReconciliation = null;
    // A foreground/privacy transition superseded this read. Retry only under
    // the currently registered App authority; the stale payload is discarded.
    resumeDurableIdentitySetupReconciliation();
    return;
  }

  if (result.status === "none") {
    activeReconciliation = null;
    useIdentitySetupStore.setState({
      activeMode: activeAttempt?.mode ?? null,
      nativeReconciliation: "ready",
      publicFailureCode: null,
      recoveryNotice: null,
      restartBlocked: false,
    });
    return;
  }

  if (result.status === "unconfirmed") {
    activeReconciliation = null;
    blockDurableReconciliation(PUBLIC_INTERRUPTION_UNKNOWN);
    return;
  }

  if (result.status === "in_progress") {
    activeReconciliation = null;
    // No timer: only a later native wake, foreground epoch, or explicit retry
    // is allowed to ask authoritative native state again.
    useIdentitySetupStore.setState({ nativeReconciliation: "checking" });
    return;
  }

  const receiptKey = durableReceiptKey(result);
  const handledStatus = handledTerminalReceipts.get(receiptKey);
  if (handledStatus !== undefined) {
    if (handledStatus !== result.status) {
      activeReconciliation = null;
      blockDurableReconciliation(PUBLIC_INTERRUPTION_UNKNOWN);
      return;
    }
    if (result.status !== "committed") {
      activeReconciliation = null;
      useIdentitySetupStore.setState({ nativeReconciliation: "ready" });
      return;
    }
    // Notification dedup is process-local, but runtime authority is not. A
    // remounted App must idempotently bootstrap and confirm identityExists for
    // its own foreground epoch before a retained COMMITTED receipt opens UI.
  }

  if (activeAttempt && activeAttempt.mode !== result.mode) {
    activeReconciliation = null;
    blockDurableReconciliation(PUBLIC_INTERRUPTION_UNKNOWN);
    return;
  }
  // Native owns a single setup ceremony. A matching durable terminal receipt
  // supersedes the process-local Promise; its later settlement is ignored.
  if (activeAttempt) activeAttempt = null;

  if (result.status === "committed") {
    void Promise.resolve()
      .then(() => continuation.onIdentityPresent(authorityEpoch))
      .then(
        (refresh) => finishDurableCommitRefresh(
          continuation,
          authorityEpoch,
          token,
          receiptKey,
          refresh === "confirmed" || refresh === "superseded"
            ? refresh
            : "failed",
        ),
        () => finishDurableCommitRefresh(
          continuation,
          authorityEpoch,
          token,
          receiptKey,
          "failed",
        ),
      );
    return;
  }

  activeReconciliation = null;
  handledTerminalReceipts.set(receiptKey, result.status);
  if (result.status === "user_cancelled") {
    useIdentitySetupStore.setState({
      activeMode: null,
      nativeReconciliation: "ready",
      publicFailureCode: null,
      recoveryNotice: result.mode === "create" ? PUBLIC_CREATE_CANCELLED : null,
      restartBlocked: false,
    });
    return;
  }

  useIdentitySetupStore.setState({
    activeMode: null,
    nativeReconciliation: "ready",
    publicFailureCode: "VEIL-SETUP-002",
    recoveryNotice: result.mode === "create"
      ? PUBLIC_CREATE_INTERRUPTION_ABSENT
      : PUBLIC_DURABLE_RESTORE_INTERRUPTION_ABSENT,
    // Native reconciliation already performed the strict vault-absence read.
    // The public notice remains visible, but it is not a global restart block.
    restartBlocked: false,
  });
}

function finishDurableCommitRefresh(
  continuation: RegisteredContinuation,
  authorityEpoch: number,
  token: number,
  receiptKey: string,
  refresh: "confirmed" | "superseded" | "failed",
): void {
  if (!ownsActiveReconciliation(continuation, token)) return;
  activeReconciliation = null;
  if (refresh === "failed") {
    blockDurableReconciliation(PUBLIC_REFRESH_RECOVERY);
    return;
  }
  if (refresh === "superseded") {
    useIdentitySetupStore.setState({ nativeReconciliation: "checking" });
    resumeDurableIdentitySetupReconciliation();
    return;
  }
  const durableAuthorityEpoch =
    getDurableReconciliationAuthorityEpoch(continuation);
  if (durableAuthorityEpoch === null) {
    // The callback was superseded by privacy/background. It did not fail; keep
    // the route closed and let the next foreground wake replay the receipt.
    useIdentitySetupStore.setState({ nativeReconciliation: "checking" });
    return;
  }
  const confirmedAuthorityEpoch = authorityEpoch + 1;
  if (!Number.isSafeInteger(confirmedAuthorityEpoch)) {
    blockDurableReconciliation(PUBLIC_REFRESH_RECOVERY);
    return;
  }
  const runtimeAuthorityEpoch = continuation.getAuthorityEpoch();
  if (
    durableAuthorityEpoch !== confirmedAuthorityEpoch ||
    runtimeAuthorityEpoch !== confirmedAuthorityEpoch
  ) {
    if (
      durableAuthorityEpoch === authorityEpoch ||
      runtimeAuthorityEpoch === null
    ) {
      // A literal `confirmed` without the exact successor Ready authority is a
      // malformed attestation, not success.
      blockDurableReconciliation(PUBLIC_REFRESH_RECOVERY);
      return;
    }
    // Authority advanced again after the callback attested its successor.
    // Retain the receipt and replay it under the new exact foreground epoch.
    useIdentitySetupStore.setState({ nativeReconciliation: "checking" });
    resumeDurableIdentitySetupReconciliation();
    return;
  }

  handledTerminalReceipts.set(receiptKey, "committed");
  useIdentitySetupStore.setState({
    activeMode: null,
    nativeReconciliation: "ready",
    publicFailureCode: null,
    recoveryNotice: null,
    restartBlocked: false,
  });
}

function ownsActiveReconciliation(
  continuation: RegisteredContinuation,
  token: number,
): boolean {
  return activeReconciliation?.token === token
    && activeReconciliation.continuationId === continuation.id
    && registeredContinuation === continuation;
}

function getDurableReconciliationAuthorityEpoch(
  continuation: RegisteredContinuation,
): number | null {
  return continuation.getDurableReconciliationAuthorityEpoch
    ? continuation.getDurableReconciliationAuthorityEpoch()
    : continuation.getAuthorityEpoch();
}

function durableReceiptKey(
  result: Exclude<NativeIdentitySetupReconciliationResult, { status: "none" | "unconfirmed" }>,
): string {
  return `${result.attemptId}:${result.processIncarnationId}:${result.mode}`;
}

function blockDurableReconciliation(recoveryNotice: string): void {
  useIdentitySetupStore.setState({
    activeMode: null,
    nativeReconciliation: "blocked",
    publicFailureCode: "VEIL-SETUP-002",
    recoveryNotice,
    restartBlocked: true,
  });
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

function invalidateReconciliationOwnedBy(continuationId: number | null): void {
  if (
    continuationId === null
    || activeReconciliation?.continuationId !== continuationId
  ) return;
  activeReconciliation = null;
}

function normalizeVerification(result: unknown): IdentityVerificationResult {
  return result === "present" || result === "absent" ? result : "unknown";
}

export function resetIdentitySetupStoreForTests(): void {
  activeAttempt = null;
  registeredContinuation = null;
  activeReconciliation = null;
  handledTerminalReceipts.clear();
  presentationAttemptId = 0;
  // Never allow a late Promise from a previous test/attempt to correlate with
  // newly allocated process-local identifiers.
  nextAttemptId += 1;
  nextContinuationId += 1;
  nextVerificationToken += 1;
  nextReconciliationToken += 1;
  useIdentitySetupStore.setState(initialIdentitySetupState, true);
}
