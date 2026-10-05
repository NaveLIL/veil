import React, { useEffect, useState } from "react";
import {
  ScrollView,
  StyleSheet,
  View,
} from "react-native";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import { SafeAreaProvider, SafeAreaView } from "react-native-safe-area-context";
import { StatusBar } from "expo-status-bar";

import { PrivacyCurtain } from "./src/components/runtime/PrivacyCurtain";
import { PublicFailureCard } from "./src/components/runtime/PublicFailureCard";
import { SecureRuntimeGate } from "./src/components/runtime/SecureRuntimeGate";
import type { PublicFailureCodeV1 } from "./src/contracts/publicFailureCodesV1";
import { useReducedMotionPreference } from "./src/hooks/useReducedMotionPreference";
import { useVeilRuntimeLifecycle } from "./src/hooks/useVeilRuntimeLifecycle";
import { colors, radii, spacing } from "./src/lib/theme";
import type { VeilMobileRuntimeSnapshot } from "./src/native/runtime";
import { setAuthenticatedContentReady } from "./src/native/screenCapture";
import ChatListScreen from "./src/screens/ChatListScreen";
import OnboardingScreen from "./src/screens/OnboardingScreen";
import {
  registerIdentitySetupContinuation,
  resumeIdentitySetupContinuation,
  retryIdentitySetupReconciliation,
  useIdentitySetupStore,
} from "./src/stores/identitySetup";
import {
  canRenderChat,
  useRuntimeGateStore,
} from "./src/stores/runtime";
import { useMobileSettingsStore } from "./src/stores/settings";
import { AccountAppearanceProvider } from './src/presentation/appearance/AccountAppearance';
import { ModalBlurBoundary } from './src/interfacePreview/LiveBlur';
import { VeilState } from './src/interfacePreview/VeilState';
import { usePresentation } from './src/interfacePreview/PresentationContext';
import { AccessibilityFocusBoundary } from './src/interfacePreview/AccessibilityFocusBoundary';
import { Button } from './src/interfacePreview/Primitives';
import { accountStartupState } from './src/presenters/accountStartup';

export default function App() {
  return <AccountAppearanceProvider><AccessibilityFocusBoundary><ModalBlurBoundary>
    <RuntimeApplication />
  </ModalBlurBoundary></AccessibilityFocusBoundary></AccountAppearanceProvider>;
}
function RuntimeApplication() {
  const runtime = useVeilRuntimeLifecycle();
  const verifyIdentityPresence = runtime.verifyIdentityPresence;
  const retryIdentityBootstrap = runtime.retryBootstrap;
  const reducedMotion = useReducedMotionPreference();
  const phase = useRuntimeGateStore((state) => state.phase);
  const snapshot = useRuntimeGateStore((state) => state.snapshot);
  const curtainVisible = useRuntimeGateStore((state) => state.curtainVisible);
  const requiresExplicitReopen = useRuntimeGateStore((state) => state.requiresExplicitReopen);
  const operation = useRuntimeGateStore((state) => state.operation);
  const publicFailureCode = useRuntimeGateStore((state) => state.publicFailureCode);
  const identityReconciliation = useIdentitySetupStore(
    (state) => state.nativeReconciliation,
  );
  const allowReadyScreenshots = useMobileSettingsStore(
    (state) => state.allowReadyScreenshots,
  );

  const chatReady = canRenderChat(snapshot, requiresExplicitReopen, publicFailureCode);
  const captureReady = phase === "ready"
    && identityReconciliation === "ready"
    && chatReady
    && !curtainVisible
    && operation === null
    && allowReadyScreenshots;

  useEffect(() => registerIdentitySetupContinuation({
    getAuthorityEpoch: () => {
      const gate = useRuntimeGateStore.getState();
      return gate.phase === "ready" && !gate.curtainVisible ? gate.epoch : null;
    },
    getDurableReconciliationAuthorityEpoch: () => {
      const gate = useRuntimeGateStore.getState();
      return gate.curtainVisible || gate.phase === "privacy" ? null : gate.epoch;
    },
    verifyIdentity: verifyIdentityPresence,
    onIdentityPresent: async (expectedDurableAuthorityEpoch) => {
      const before = useRuntimeGateStore.getState();
      if (
        expectedDurableAuthorityEpoch !== undefined
        && (
          before.curtainVisible
          || before.phase === "privacy"
          || before.epoch !== expectedDurableAuthorityEpoch
        )
      ) {
        return "superseded" as const;
      }
      await retryIdentityBootstrap();
      const gate = useRuntimeGateStore.getState();
      if (
        expectedDurableAuthorityEpoch !== undefined
        && gate.epoch !== expectedDurableAuthorityEpoch + 1
      ) {
        return "superseded" as const;
      }
      if (
        gate.phase !== "ready"
        || gate.curtainVisible
        || gate.snapshot?.identityExists !== true
      ) {
        // The controller catches native diagnostics internally. Reject with a
        // local sentinel so setup presentation can fail closed without text.
        throw new Error("identity-present bootstrap was not confirmed");
      }
      return "confirmed" as const;
    },
    enableDurableReconciliation: true,
  }), [retryIdentityBootstrap, verifyIdentityPresence]);

  useEffect(() => {
    // A native result may arrive while RecoveryActivity owns the foreground.
    // Resume it only after this exact App runtime epoch becomes authoritative.
    resumeIdentitySetupContinuation();
  }, [curtainVisible, phase, snapshot?.runtimeRevision]);

  useEffect(() => {
    // Native owns the actual policy. In release, a renderer request can never
    // clear FLAG_SECURE; debug builds allow only this fully verified Ready UI.
    void setAuthenticatedContentReady(captureReady);
    return () => {
      void setAuthenticatedContentReady(false);
    };
  }, [captureReady]);

  let content: React.ReactNode;
  if (identityReconciliation === "checking") {
    content = <RuntimeBootstrap onRetry={() => void runtime.retryBootstrap()} />;
  } else if (identityReconciliation === "blocked") {
    content = (
      <RuntimeError
        code="VEIL-SETUP-002"
        onRetry={() => {
          retryIdentitySetupReconciliation();
          void runtime.retryBootstrap();
        }}
      />
    );
  } else if (phase === "bootstrapping" || phase === "privacy") {
    content = <RuntimeBootstrap onRetry={() => void runtime.retryBootstrap()} />;
  } else if (phase === "error" || !snapshot) {
    content = (
      <RuntimeError
        code={publicFailureCode ?? "VEIL-LOCAL-003"}
        onRetry={() => void runtime.retryBootstrap()}
      />
    );
  } else if (canStartNativeIdentitySetup(
    snapshot,
    publicFailureCode,
  )) {
    content = (
      <OnboardingScreen
        reducedMotion={reducedMotion}
      />
    );
  } else if (!snapshot.identityExists) {
    content = (
      <RuntimeError
        code={publicFailureCode ?? "VEIL-LOCAL-003"}
        onRetry={() => void runtime.retryBootstrap()}
      />
    );
  } else if (chatReady) {
    content = (
      <View testID="chat-runtime-ready" style={styles.flex}>
        <ChatListScreen />
      </View>
    );
  } else {
    content = (
      <SecureRuntimeGate
        snapshot={snapshot}
        requiresExplicitReopen={requiresExplicitReopen}
        operation={operation}
        publicFailureCode={publicFailureCode}
        reducedMotion={reducedMotion}
        onUnlock={() => void runtime.unlock()}
        onConnect={(origin) => void runtime.connect(origin)}
        onImportAccessPass={() => void runtime.importAccessPass()}
        onUsePendingAccessPass={(flowId) => void runtime.usePendingAccessPass(flowId)}
        onDiscardPendingAccessPass={(flowId) => void runtime.discardPendingAccessPass(flowId)}
        onRefresh={() => void runtime.refresh()}
      />
    );
  }

  return (
    <GestureHandlerRootView style={styles.root}>
      <SafeAreaProvider>
        <StatusBar style="light" translucent />
        <View
          testID={`account-state-${accountStartupState(phase, snapshot, requiresExplicitReopen, publicFailureCode)}`}
          style={styles.flex}
          pointerEvents={curtainVisible ? "none" : "auto"}
          importantForAccessibility={curtainVisible ? "no-hide-descendants" : "auto"}
        >
          {content}
        </View>
        {curtainVisible ? <PrivacyCurtain reducedMotion={reducedMotion} /> : null}
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}

export function canStartNativeIdentitySetup(
  snapshot: VeilMobileRuntimeSnapshot,
  publicFailureCode: PublicFailureCodeV1 | null,
): boolean {
  return !snapshot.identityExists
    && Number.isSafeInteger(snapshot.runtimeRevision)
    && snapshot.runtimeRevision >= 1
    && snapshot.directGeneration === null
    && snapshot.directContentRevision === null
    && snapshot.sessionState === "locked"
    && snapshot.connectionState === "disconnected"
    && !snapshot.directoryReady
    && snapshot.secureSyncState === "idle"
    && snapshot.binding === null
    && snapshot.publicFailureCodeV1 === null
    && snapshot.directConversations.length === 0
    && publicFailureCode === null;
}

function RuntimeBootstrap({ onRetry }: { onRetry: () => void }) {
  const { c } = usePresentation();
  const [slow, setSlow] = useState(false);
  useEffect(() => { const timer = setTimeout(() => setSlow(true), 10000); return () => clearTimeout(timer); }, []);
  return <View testID="runtime-bootstrap" accessibilityLabel="Проверяем защищённую сессию Veil" style={[styles.flex, {backgroundColor:c.bg}]}>
    <VeilState c={c} kind={slow ? 'unavailable' : 'loading'} title="Проверка защищённой сессии"
      detail={slow ? 'Проверка занимает больше времени. Аккаунт пока не открыт.' : 'Ожидаем состояние native runtime. Переписка ещё недоступна.'}
      action={slow ? {label:'Повторить защищённую проверку', onPress:onRetry} : undefined} />
  </View>;
}

function RuntimeError({
  code,
  onRetry,
}: {
  code: PublicFailureCodeV1;
  onRetry: () => void;
}) {
  const { c } = usePresentation();
  return (
    <SafeAreaView testID="runtime-error" style={[styles.runtimeErrorRoot, {backgroundColor:c.bg}]} edges={["top", "bottom", "left", "right"]}>
      <ScrollView
        testID="runtime-error-scroll"
        contentContainerStyle={styles.runtimeErrorContent}
        showsVerticalScrollIndicator
      >
        <View style={styles.errorCard}>
          <PublicFailureCard code={code} />
          <Button label="Повторить защищённую проверку" onPress={onRetry} c={c} />
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  flex: { flex: 1 },
  centered: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.background,
    padding: spacing.xxl,
  },
  bootstrapText: {
    color: colors.textMd,
    fontSize: 15,
    lineHeight: 22,
    textAlign: "center",
    marginTop: spacing.md,
  },
  runtimeErrorRoot: { flex: 1, backgroundColor: colors.background },
  runtimeErrorContent: {
    flexGrow: 1,
    alignItems: "center",
    justifyContent: "center",
    paddingHorizontal: spacing.xl,
    paddingVertical: spacing.xxl,
  },
  errorCard: {
    width: "100%",
    maxWidth: 460,
  },
  retryButton: {
    minHeight: 48,
    alignItems: "center",
    justifyContent: "center",
    borderRadius: radii.md,
    backgroundColor: colors.primaryDeep,
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
    marginTop: spacing.xl,
  },
  retryPressed: { opacity: 0.78 },
  retryText: { color: "#fff", fontSize: 15, fontWeight: "800", textAlign: "center" },
});
