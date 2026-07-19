import { useCallback, useEffect, useMemo, useRef } from "react";
import {
  AppState,
  type AppStateStatus,
  type EmitterSubscription,
} from "react-native";

import VeilRuntime, { type VeilMobileRuntimeSnapshot } from "../native/runtime";
import { useChatStore } from "../stores/chat";
import {
  canRenderChat,
  classifyRuntimeOperationFailure,
  conservativelyMergeRuntimeSnapshots,
  useRuntimeGateStore,
  type RuntimeOperation,
} from "../stores/runtime";

type SecureOperation = Exclude<RuntimeOperation, null>;

export interface VeilRuntimeController {
  refresh: () => Promise<void>;
  retryBootstrap: () => Promise<void>;
  verifyIdentityPresence: () => Promise<"present" | "absent" | "unknown">;
  unlock: () => Promise<void>;
  connect: (canonicalOrigin: string) => Promise<void>;
  usePendingAccessPass: (flowId: string) => Promise<void>;
  discardPendingAccessPass: (flowId: string) => Promise<void>;
}

const isActive = (state: AppStateStatus): boolean => state === "active";

/**
 * Owns the React Native side of the native account lifecycle.
 *
 * A background transition invalidates the current epoch synchronously, removes
 * the native event subscription, clears renderable Direct plaintext, and
 * starts a best-effort native lock. Foreground waits for that lock barrier and
 * a new native snapshot; it never restores an old OPEN snapshot.
 */
export function useVeilRuntimeLifecycle(): VeilRuntimeController {
  const mountedRef = useRef(false);
  const appStateRef = useRef<AppStateStatus>(AppState.currentState);
  const runtimeSubscriptionRef = useRef<EmitterSubscription | null>(null);
  const lockBarrierRef = useRef<Promise<void>>(Promise.resolve());

  const removeRuntimeSubscription = useCallback(() => {
    runtimeSubscriptionRef.current?.remove();
    runtimeSubscriptionRef.current = null;
  }, []);

  const removeRuntimeSubscriptionIfOwned = useCallback((
    subscription: EmitterSubscription,
  ): void => {
    if (runtimeSubscriptionRef.current !== subscription) return;
    runtimeSubscriptionRef.current = null;
    subscription.remove();
  }, []);

  const epochIsCurrent = useCallback((epoch: number): boolean => {
    const state = useRuntimeGateStore.getState();
    return mountedRef.current && state.epoch === epoch && isActive(appStateRef.current);
  }, []);

  const reconcileRenderableChat = useCallback((
    epoch: number,
  ): void => {
    const gate = useRuntimeGateStore.getState();
    const committedSnapshot = gate.epoch === epoch
      && gate.phase === "ready"
      && !gate.curtainVisible
      ? gate.snapshot
      : null;
    if (
      committedSnapshot
      && canRenderChat(
        committedSnapshot,
        gate.requiresExplicitReopen,
        gate.publicFailureCode,
      )
    ) {
      const before = useChatStore.getState();
      const selectedBefore = before.selectedDmId;
      const contentRevisionBefore = before.directContentRevision;
      before.hydrateRuntimeDirectory(committedSnapshot);
      const after = useChatStore.getState();
      if (
        selectedBefore !== null
        && after.selectedDmId === selectedBefore
        && contentRevisionBefore !== null
        && after.directContentRevision !== null
        && after.directContentRevision > contentRevisionBefore
      ) {
        // Native emitted an aggregate visible-content invalidation for this
        // exact Direct generation. It may represent a quarantine revocation,
        // so the store clears the explicitly selected projection immediately
        // before asking native for an authoritative replacement.
        void after.loadSelectedDirectMessages();
      }
      return;
    }
    useChatStore.getState().clearRenderableChat();
  }, []);

  const attachAfterFreshSnapshot = useCallback(async (
    epoch: number,
    barrier: Promise<void> = Promise.resolve(),
  ): Promise<void> => {
    removeRuntimeSubscription();
    let subscription: EmitterSubscription | null = null;
    try {
      await barrier;
      if (!epochIsCurrent(epoch)) return;

      // Read once before subscribing so module/auth failures cannot leave an
      // event listener attached to an unverified runtime.
      await VeilRuntime.getSnapshot();
      if (!epochIsCurrent(epoch)) return;

      let handshaking = true;
      let bufferedSnapshot: VeilMobileRuntimeSnapshot | null = null;
      subscription = VeilRuntime.subscribe((snapshot) => {
        if (handshaking) {
          // Keep the latest event that arrives after subscription but before
          // the confirming read is committed. Dropping it could publish a
          // stale OPEN/LOCKED state for this foreground epoch.
          bufferedSnapshot = snapshot;
          return;
        }
        useRuntimeGateStore.getState().acceptRuntimeEvent(epoch, snapshot);
        // Reconcile the snapshot actually committed by the runtime gate. A
        // lower-revision event may have been ignored and must not clear the
        // newer directory or plaintext projection.
        reconcileRenderableChat(epoch);
      });
      if (!epochIsCurrent(epoch)) {
        subscription.remove();
        return;
      }
      runtimeSubscriptionRef.current = subscription;

      // Confirm again after subscription. Events racing this read are either
      // represented by this snapshot or accepted after the gate becomes ready.
      const confirmed = await VeilRuntime.getSnapshot();
      if (!epochIsCurrent(epoch)) {
        removeRuntimeSubscriptionIfOwned(subscription);
        return;
      }
      // JavaScript callbacks cannot interleave these synchronous statements:
      // an event delivered before this point is buffered, and one delivered
      // afterwards sees a READY gate and is applied normally.
      const latest = bufferedSnapshot
        ? conservativelyMergeRuntimeSnapshots(confirmed, bufferedSnapshot)
        : confirmed;
      handshaking = false;
      useRuntimeGateStore.getState().commitFreshSnapshot(epoch, latest);
      reconcileRenderableChat(epoch);
    } catch (error) {
      if (subscription) removeRuntimeSubscriptionIfOwned(subscription);
      if (!epochIsCurrent(epoch)) return;
      removeRuntimeSubscription();
      useChatStore.getState().clearRenderableChat();
      useRuntimeGateStore.getState().failFreshSnapshot(
        epoch,
        classifyRuntimeOperationFailure(error),
      );
    }
  }, [
    epochIsCurrent,
    reconcileRenderableChat,
    removeRuntimeSubscription,
    removeRuntimeSubscriptionIfOwned,
  ]);

  useEffect(() => {
    mountedRef.current = true;
    appStateRef.current = AppState.currentState;

    if (isActive(appStateRef.current)) {
      const epoch = useRuntimeGateStore.getState().beginBootstrap();
      void attachAfterFreshSnapshot(epoch);
    } else {
      useRuntimeGateStore.getState().enterPrivacy();
      useChatStore.getState().clearRenderableChat();
      lockBarrierRef.current = Promise.resolve()
        .then(() => VeilRuntime.lock())
        .then(() => undefined, () => undefined);
    }

    const appStateSubscription = AppState.addEventListener("change", (nextState) => {
      const wasActive = isActive(appStateRef.current);
      appStateRef.current = nextState;

      if (!isActive(nextState)) {
        // inactive -> background is one privacy transition, not two lock calls.
        if (!wasActive) return;
        removeRuntimeSubscription();
        useRuntimeGateStore.getState().enterPrivacy();
        useChatStore.getState().clearRenderableChat();
        lockBarrierRef.current = Promise.resolve()
          .then(() => VeilRuntime.lock())
          // Lock is fail-closed UI policy. Never surface native details here.
          .then(() => undefined, () => undefined);
        return;
      }

      if (wasActive) return;
      const epoch = useRuntimeGateStore.getState().enterForeground();
      void attachAfterFreshSnapshot(epoch, lockBarrierRef.current);
    });

    return () => {
      mountedRef.current = false;
      removeRuntimeSubscription();
      appStateSubscription.remove();
      useChatStore.getState().clearRenderableChat();
    };
  }, [attachAfterFreshSnapshot, removeRuntimeSubscription]);

  const runOperation = useCallback(async (
    operation: SecureOperation,
    action: () => Promise<unknown>,
    explicitReopen = false,
  ): Promise<void> => {
    const epoch = useRuntimeGateStore.getState().beginOperation(operation);
    if (epoch === null) return;
    try {
      await action();
      if (!epochIsCurrent(epoch)) return;
      const snapshot = await VeilRuntime.getSnapshot();
      if (!epochIsCurrent(epoch)) return;
      useRuntimeGateStore.getState().finishOperation(epoch, snapshot, explicitReopen);
      reconcileRenderableChat(epoch);
    } catch (error) {
      if (!epochIsCurrent(epoch)) return;
      useChatStore.getState().clearRenderableChat();
      const operationFailure = classifyRuntimeOperationFailure(error);
      let freshSnapshot: VeilMobileRuntimeSnapshot | null = null;
      try {
        freshSnapshot = await VeilRuntime.getSnapshot();
      } catch {
        // The rejected operation no longer has an authoritative native state
        // to reconcile against. Keep any prior sanitized snapshot, but expose
        // only the unknown fail-closed outcome.
      }
      if (!epochIsCurrent(epoch)) return;
      useRuntimeGateStore.getState().failOperation(
        epoch,
        freshSnapshot === null ? "VEIL-RUNTIME-999" : operationFailure,
        freshSnapshot,
      );
      reconcileRenderableChat(epoch);
    }
  }, [epochIsCurrent, reconcileRenderableChat]);

  const refresh = useCallback(async (): Promise<void> => {
    await runOperation("refreshing", () => VeilRuntime.getSnapshot());
  }, [runOperation]);

  const retryBootstrap = useCallback(async (): Promise<void> => {
    if (!mountedRef.current || !isActive(appStateRef.current)) return;
    const epoch = useRuntimeGateStore.getState().beginBootstrap();
    await attachAfterFreshSnapshot(epoch, lockBarrierRef.current);
  }, [attachAfterFreshSnapshot]);

  const verifyIdentityPresence = useCallback(async (): Promise<
    "present" | "absent" | "unknown"
  > => {
    if (!mountedRef.current || !isActive(appStateRef.current)) return "unknown";
    const gate = useRuntimeGateStore.getState();
    const epoch = gate.epoch;
    if (gate.phase !== "ready" || gate.curtainVisible) return "unknown";
    try {
      await lockBarrierRef.current;
      if (!epochIsCurrent(epoch)) return "unknown";
      const identityExists = await VeilRuntime.verifyIdentityPresence();
      if (!epochIsCurrent(epoch)) return "unknown";
      return identityExists ? "present" : "absent";
    } catch {
      // A failed or superseded read is ambiguous. Never tell the user to
      // destroy recovery material without an authoritative absent snapshot.
      return "unknown";
    }
  }, [epochIsCurrent]);

  const unlock = useCallback(async (): Promise<void> => {
    await runOperation("unlocking", () => VeilRuntime.openSession(), true);
  }, [runOperation]);

  const connect = useCallback(async (canonicalOrigin: string): Promise<void> => {
    // A reconnect can change the authenticated account/origin binding. Drop
    // the old directory and plaintext before native work begins.
    useChatStore.getState().clearRenderableChat();
    await runOperation("connecting", () => VeilRuntime.connect(canonicalOrigin));
  }, [runOperation]);

  const usePendingAccessPass = useCallback(async (flowId: string): Promise<void> => {
    const current = useRuntimeGateStore.getState();
    const pending = current.snapshot?.pendingAccessPass;
    if (!pending || pending.flowId !== flowId) return;

    useChatStore.getState().clearRenderableChat();
    await runOperation("using_access_pass", async () => {
      const state = useRuntimeGateStore.getState();
      if (state.requiresExplicitReopen || state.snapshot?.sessionState !== "open") {
        await VeilRuntime.openSession();
      }
      await VeilRuntime.connectPendingAccessPass(flowId);
    }, true);
  }, [runOperation]);

  const discardPendingAccessPass = useCallback(async (flowId: string): Promise<void> => {
    const pending = useRuntimeGateStore.getState().snapshot?.pendingAccessPass;
    if (!pending || pending.flowId !== flowId) return;
    await runOperation(
      "discarding_access_pass",
      () => VeilRuntime.cancelPendingAccessPass(flowId),
    );
  }, [runOperation]);

  return useMemo(() => ({
    refresh,
    retryBootstrap,
    verifyIdentityPresence,
    unlock,
    connect,
    usePendingAccessPass,
    discardPendingAccessPass,
  }), [
    connect,
    discardPendingAccessPass,
    refresh,
    retryBootstrap,
    unlock,
    usePendingAccessPass,
    verifyIdentityPresence,
  ]);
}
