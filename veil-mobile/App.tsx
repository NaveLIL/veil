import React, { useEffect } from "react";
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
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
} from "./src/stores/identitySetup";
import {
  canRenderChat,
  useRuntimeGateStore,
} from "./src/stores/runtime";
import { useMobileSettingsStore } from "./src/stores/settings";

export default function App() {
  const runtime = useVeilRuntimeLifecycle();
  const reducedMotion = useReducedMotionPreference();
  const phase = useRuntimeGateStore((state) => state.phase);
  const snapshot = useRuntimeGateStore((state) => state.snapshot);
  const curtainVisible = useRuntimeGateStore((state) => state.curtainVisible);
  const requiresExplicitReopen = useRuntimeGateStore((state) => state.requiresExplicitReopen);
  const operation = useRuntimeGateStore((state) => state.operation);
  const publicFailureCode = useRuntimeGateStore((state) => state.publicFailureCode);
  const allowReadyScreenshots = useMobileSettingsStore(
    (state) => state.allowReadyScreenshots,
  );

  const chatReady = canRenderChat(snapshot, requiresExplicitReopen);
  const captureReady = phase === "ready"
    && chatReady
    && !curtainVisible
    && operation === null
    && allowReadyScreenshots;

  useEffect(() => registerIdentitySetupContinuation({
    getAuthorityEpoch: () => {
      const gate = useRuntimeGateStore.getState();
      return gate.phase === "ready" && !gate.curtainVisible ? gate.epoch : null;
    },
    verifyIdentity: runtime.verifyIdentityPresence,
    onIdentityPresent: runtime.retryBootstrap,
  }), [runtime.retryBootstrap, runtime.verifyIdentityPresence]);

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
  if (phase === "bootstrapping" || phase === "privacy") {
    content = <RuntimeBootstrap reducedMotion={reducedMotion} />;
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
    && snapshot.directConversations.length === 0
    && publicFailureCode === null;
}

function RuntimeBootstrap({ reducedMotion }: { reducedMotion: boolean }) {
  return (
    <View
      testID="runtime-bootstrap"
      accessibilityRole="progressbar"
      accessibilityLabel="Verifying secure mobile runtime"
      style={styles.centered}
    >
      {reducedMotion ? null : <ActivityIndicator color={colors.primaryHi} />}
      <Text style={styles.bootstrapText}>Verifying native session...</Text>
    </View>
  );
}

function RuntimeError({
  code,
  onRetry,
}: {
  code: PublicFailureCodeV1;
  onRetry: () => void;
}) {
  return (
    <SafeAreaView testID="runtime-error" style={styles.runtimeErrorRoot} edges={["top", "bottom"]}>
      <ScrollView
        testID="runtime-error-scroll"
        contentContainerStyle={styles.runtimeErrorContent}
        showsVerticalScrollIndicator
      >
        <View style={styles.errorCard}>
          <PublicFailureCard code={code} />
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="Try secure verification again"
            onPress={onRetry}
            style={({ pressed }) => [styles.retryButton, pressed && styles.retryPressed]}
          >
            <Text style={styles.retryText}>Try secure verification again</Text>
          </Pressable>
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
