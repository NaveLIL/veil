import React, { useEffect } from "react";
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { StatusBar } from "expo-status-bar";

import { PrivacyCurtain } from "./src/components/runtime/PrivacyCurtain";
import { SecureRuntimeGate } from "./src/components/runtime/SecureRuntimeGate";
import { useReducedMotionPreference } from "./src/hooks/useReducedMotionPreference";
import { useVeilRuntimeLifecycle } from "./src/hooks/useVeilRuntimeLifecycle";
import { colors, radii, spacing } from "./src/lib/theme";
import { setAuthenticatedContentReady } from "./src/native/screenCapture";
import ChatListScreen from "./src/screens/ChatListScreen";
import OnboardingScreen from "./src/screens/OnboardingScreen";
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
  const publicError = useRuntimeGateStore((state) => state.publicError);
  const allowReadyScreenshots = useMobileSettingsStore(
    (state) => state.allowReadyScreenshots,
  );

  const chatReady = canRenderChat(snapshot, requiresExplicitReopen);
  const captureReady = phase === "ready"
    && chatReady
    && !curtainVisible
    && operation === null
    && allowReadyScreenshots;

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
        message={publicError}
        onRetry={() => void runtime.retryBootstrap()}
      />
    );
  } else if (!snapshot.identityExists) {
    content = (
      <OnboardingScreen
        reducedMotion={reducedMotion}
        onVerifyIdentity={async () => {
          const verification = await runtime.verifyIdentityPresence();
          if (verification === "present") void runtime.retryBootstrap();
          return verification;
        }}
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
        publicError={publicError}
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
  message,
  onRetry,
}: {
  message: string | null;
  onRetry: () => void;
}) {
  return (
    <View testID="runtime-error" accessibilityRole="alert" style={styles.centered}>
      <View style={styles.errorCard}>
        <Text accessibilityRole="header" style={styles.errorTitle}>Secure runtime unavailable</Text>
        <Text style={styles.errorBody}>
          {message ?? "Veil could not verify the native account boundary. No messages were opened."}
        </Text>
        <Pressable
          accessibilityRole="button"
          onPress={onRetry}
          style={({ pressed }) => [styles.retryButton, pressed && styles.retryPressed]}
        >
          <Text style={styles.retryText}>Try secure verification again</Text>
        </Pressable>
      </View>
    </View>
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
  errorCard: {
    width: "100%",
    maxWidth: 460,
    borderRadius: radii.xl,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.destructiveBorder,
    backgroundColor: colors.surfaceSolid,
    padding: spacing.xl,
  },
  errorTitle: { color: colors.textHi, fontSize: 21, fontWeight: "800", textAlign: "center" },
  errorBody: {
    color: colors.textMd,
    fontSize: 15,
    lineHeight: 22,
    textAlign: "center",
    marginTop: spacing.sm,
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
