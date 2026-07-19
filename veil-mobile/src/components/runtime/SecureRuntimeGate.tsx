import React, { useEffect, useMemo, useState } from "react";
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import { PhaseShiftMark } from "../brand/PhaseShiftMark";
import { PublicFailureCard } from "./PublicFailureCard";
import type { PublicFailureCodeV1 } from "../../contracts/publicFailureCodesV1";
import { colors, radii, spacing, typography } from "../../lib/theme";
import type { VeilMobileRuntimeSnapshot } from "../../native/runtime";
import {
  hasExactAuthenticatedBinding,
  type RuntimeOperation,
} from "../../stores/runtime";

interface SecureRuntimeGateProps {
  snapshot: VeilMobileRuntimeSnapshot;
  requiresExplicitReopen: boolean;
  operation: RuntimeOperation;
  publicFailureCode: PublicFailureCodeV1 | null;
  reducedMotion: boolean;
  onUnlock: () => void;
  onConnect: (canonicalOrigin: string) => void;
  onUsePendingAccessPass: (flowId: string) => void;
  onDiscardPendingAccessPass: (flowId: string) => void;
  onRefresh: () => void;
}

const DEFAULT_ORIGIN = "https://veil.erez.pro";

export function SecureRuntimeGate({
  snapshot,
  requiresExplicitReopen,
  operation,
  publicFailureCode,
  reducedMotion,
  onUnlock,
  onConnect,
  onUsePendingAccessPass,
  onDiscardPendingAccessPass,
  onRefresh,
}: SecureRuntimeGateProps) {
  const pending = snapshot.pendingAccessPass;
  const suggestedOrigin = pending?.canonicalOrigin
    ?? snapshot.binding?.canonicalServerOrigin
    ?? DEFAULT_ORIGIN;
  const [origin, setOrigin] = useState(suggestedOrigin);
  const busy = operation !== null;

  useEffect(() => {
    if (pending?.canonicalOrigin) setOrigin(pending.canonicalOrigin);
  }, [pending?.canonicalOrigin]);

  const status = useMemo(() => {
    if (requiresExplicitReopen) {
      return {
        title: "Unlock required",
        body: "Veil locked this account when the app left the foreground. Reopen it explicitly to continue.",
      };
    }
    if (snapshot.sessionState === "locked" || snapshot.sessionState === "error") {
      return {
        title: "Local account locked",
        body: "Your recovery material remains inside the encrypted native vault.",
      };
    }
    if (snapshot.sessionState === "opening" || snapshot.sessionState === "closing") {
      return {
        title: "Securing local account",
        body: "Waiting for the native encrypted session to settle.",
      };
    }
    if (snapshot.connectionState === "connecting") {
      return {
        title: "Authenticating Veil Node",
        body: "Establishing the native encrypted transport and account binding.",
      };
    }
    if (snapshot.connectionState === "connected" && !snapshot.directoryReady) {
      switch (snapshot.secureSyncState) {
        case "publishing_keys":
          return {
            title: "Publishing device keys",
            body: "Preparing this device for authenticated encrypted conversations.",
          };
        case "syncing_directory":
          return {
            title: "Verifying conversations",
            body: "Loading the authenticated conversation directory into encrypted local storage.",
          };
        case "syncing_history":
          return {
            title: "Restoring encrypted history",
            body: "Validating and storing supported Direct messages before live chat can open.",
          };
        case "history_synchronized":
          return {
            title: "Reconciling live messages",
            body: "History is synchronized. Veil is still waiting for safe live-message reconciliation.",
          };
        default:
          return {
            title: "Secure sync is not ready",
            body: "The account is authenticated, but native secure synchronization is still incomplete.",
          };
      }
    }
    return {
      title: "Connect to your Veil Node",
      body: "Only the canonical server origin crosses this UI boundary. Authentication remains native.",
    };
  }, [
    requiresExplicitReopen,
    snapshot.connectionState,
    snapshot.directoryReady,
    snapshot.secureSyncState,
    snapshot.sessionState,
  ]);

  const needsUnlock = requiresExplicitReopen || snapshot.sessionState !== "open";
  const canEnterOrigin = !needsUnlock
    && (snapshot.connectionState === "disconnected" || snapshot.connectionState === "error");
  const bindingIsExact = hasExactAuthenticatedBinding(snapshot.binding);

  return (
    <SafeAreaView testID="secure-runtime-gate" style={styles.root} edges={["top", "bottom"]}>
      <KeyboardAvoidingView
        style={styles.flex}
        behavior={Platform.OS === "ios" ? "padding" : undefined}
      >
        <ScrollView
          contentContainerStyle={styles.scrollContent}
          keyboardShouldPersistTaps="handled"
          showsVerticalScrollIndicator={false}
        >
          <View style={styles.brandBlock} accessible accessibilityRole="header">
            <PhaseShiftMark size={56} testID="runtime-brand-phase-shift-mark" />
            <Text style={styles.brand}>VEIL</Text>
            <Text style={styles.brandSub}>Native secure session</Text>
          </View>

          {pending ? (
            <View testID="access-pass-review" style={[styles.card, styles.passCard]}>
              <View style={styles.cardHeader}>
                <View style={styles.statusDot} />
                <Text style={styles.eyebrow}>NODE ACCESS PASS</Text>
              </View>
              <Text style={styles.cardTitle}>Review invitation</Text>
              <Text style={styles.cardBody}>
                This pass can register one account. Its bearer never enters JavaScript.
              </Text>
              <MetadataRow label="Origin" value={pending.canonicalOrigin} testID="access-pass-origin" />
              <MetadataRow label="Reference" value={pending.tokenRef} mono testID="access-pass-reference" />
              <MetadataRow label="Expires in" value={formatTtl(pending.expiresInSeconds)} testID="access-pass-ttl" />
              <View style={styles.actionStack}>
                <ActionButton
                  testID="use-access-pass"
                  label={operation === "using_access_pass" ? "Opening securely..." : "Use access pass"}
                  onPress={() => onUsePendingAccessPass(pending.flowId)}
                  disabled={busy}
                  primary
                />
                <ActionButton
                  testID="discard-access-pass"
                  label="Discard invitation"
                  onPress={() => onDiscardPendingAccessPass(pending.flowId)}
                  disabled={busy}
                />
              </View>
            </View>
          ) : null}

          <View style={styles.card}>
            <Text accessibilityRole="header" style={styles.cardTitle}>{status.title}</Text>
            <Text style={styles.cardBody}>{status.body}</Text>

            {publicFailureCode ? (
              <View testID="runtime-public-error">
                <PublicFailureCard code={publicFailureCode} compact />
              </View>
            ) : null}

            {needsUnlock ? (
              <ActionButton
                testID="unlock-account"
                label={operation === "unlocking" ? "Unlocking..." : "Unlock local account"}
                onPress={onUnlock}
                disabled={busy || snapshot.sessionState === "opening" || snapshot.sessionState === "closing"}
                primary
              />
            ) : null}

            {canEnterOrigin ? (
              <View style={styles.form}>
                <Text style={styles.inputLabel}>Canonical Veil Node origin</Text>
                <TextInput
                  testID="node-origin-input"
                  accessibilityLabel="Canonical Veil Node origin"
                  value={origin}
                  onChangeText={setOrigin}
                  autoCapitalize="none"
                  autoCorrect={false}
                  spellCheck={false}
                  keyboardType="url"
                  textContentType="URL"
                  placeholder="https://veil.example"
                  placeholderTextColor={colors.textXLo}
                  style={styles.input}
                />
                <ActionButton
                  testID="connect-node"
                  label={operation === "connecting" ? "Connecting..." : "Connect securely"}
                  onPress={() => onConnect(origin)}
                  disabled={busy || !origin.trim()}
                  primary
                />
              </View>
            ) : null}

            {!needsUnlock && snapshot.connectionState === "connected" ? (
              <View style={styles.bindingBox}>
                <Text style={styles.bindingState}>
                  {bindingIsExact ? "Authenticated binding verified" : "Binding verification unavailable"}
                </Text>
                {snapshot.binding ? (
                  <Text style={styles.bindingOrigin}>{snapshot.binding.canonicalServerOrigin}</Text>
                ) : null}
                <ActionButton
                  testID="refresh-runtime"
                  label={operation === "refreshing" ? "Refreshing..." : "Refresh secure state"}
                  onPress={onRefresh}
                  disabled={busy}
                />
              </View>
            ) : null}

            {!reducedMotion && busy && operation !== "unlocking" && operation !== "connecting" ? (
              <ActivityIndicator
                accessibilityLabel="Secure action in progress"
                color={colors.primaryHi}
                style={styles.activity}
              />
            ) : null}
          </View>

          <Text style={styles.footer}>
            Messages stay hidden until the native session, exact account binding, and verified directory are all ready.
          </Text>
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

function MetadataRow({
  label,
  value,
  mono = false,
  testID,
}: {
  label: string;
  value: string;
  mono?: boolean;
  testID?: string;
}) {
  return (
    <View style={styles.metadataRow}>
      <Text style={styles.metadataLabel}>{label}</Text>
      <Text testID={testID} selectable={false} style={[styles.metadataValue, mono && styles.mono]}>
        {value}
      </Text>
    </View>
  );
}

function ActionButton({
  label,
  onPress,
  disabled,
  primary = false,
  testID,
}: {
  label: string;
  onPress: () => void;
  disabled: boolean;
  primary?: boolean;
  testID?: string;
}) {
  return (
    <Pressable
      testID={testID}
      accessibilityRole="button"
      accessibilityState={{ disabled, busy: label.endsWith("...") }}
      onPress={onPress}
      disabled={disabled}
      style={({ pressed }) => [
        styles.button,
        primary ? styles.primaryButton : styles.secondaryButton,
        pressed && !disabled && styles.buttonPressed,
        disabled && styles.buttonDisabled,
      ]}
    >
      <Text style={[styles.buttonText, !primary && styles.secondaryButtonText]}>{label}</Text>
    </Pressable>
  );
}

function formatTtl(seconds: number): string {
  const safeSeconds = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(safeSeconds / 60);
  const remainder = safeSeconds % 60;
  return `${minutes}m ${String(remainder).padStart(2, "0")}s`;
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  flex: { flex: 1 },
  scrollContent: {
    flexGrow: 1,
    justifyContent: "center",
    width: "100%",
    maxWidth: 520,
    alignSelf: "center",
    paddingHorizontal: spacing.xl,
    paddingVertical: spacing.xxl,
    gap: spacing.lg,
  },
  brandBlock: { alignItems: "center", marginBottom: spacing.sm },
  brand: {
    color: colors.textHi,
    fontSize: 17,
    fontWeight: "800",
    letterSpacing: 5,
    marginTop: spacing.md,
  },
  brandSub: { color: colors.textLo, fontSize: 13, marginTop: spacing.xs },
  card: {
    backgroundColor: colors.surfaceSolid,
    borderRadius: radii.xl,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    padding: spacing.xl,
    gap: spacing.md,
  },
  passCard: { borderColor: "rgba(155,138,251,0.32)" },
  cardHeader: { flexDirection: "row", alignItems: "center", gap: spacing.sm },
  statusDot: { width: 8, height: 8, borderRadius: 4, backgroundColor: colors.primaryHi },
  eyebrow: { color: colors.primaryHi, fontSize: 11, fontWeight: "800", letterSpacing: 1.4 },
  cardTitle: { color: colors.textHi, fontSize: 21, lineHeight: 27, fontWeight: "800" },
  cardBody: { color: colors.textMd, fontSize: 15, lineHeight: 22 },
  metadataRow: {
    minHeight: 48,
    justifyContent: "center",
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: colors.border,
    paddingVertical: spacing.sm,
  },
  metadataLabel: { color: colors.textLo, fontSize: 12, fontWeight: "700", marginBottom: 4 },
  metadataValue: { color: colors.textHi, fontSize: 14, lineHeight: 20 },
  mono: { fontFamily: typography.mono, letterSpacing: 1 },
  actionStack: { gap: spacing.sm, marginTop: spacing.xs },
  form: { gap: spacing.sm, marginTop: spacing.xs },
  inputLabel: { color: colors.textMd, fontSize: 13, fontWeight: "700" },
  input: {
    minHeight: 52,
    borderRadius: radii.md,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: "rgba(255,255,255,0.12)",
    backgroundColor: colors.surfaceLow,
    color: colors.textHi,
    fontSize: 16,
    paddingHorizontal: spacing.lg,
  },
  button: {
    minHeight: 48,
    borderRadius: radii.md,
    alignItems: "center",
    justifyContent: "center",
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
  },
  primaryButton: { backgroundColor: colors.primaryDeep },
  secondaryButton: {
    backgroundColor: colors.surfaceLow,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
  },
  buttonPressed: { opacity: 0.78 },
  buttonDisabled: { opacity: 0.46 },
  buttonText: { color: "#fff", fontSize: 15, fontWeight: "800", textAlign: "center" },
  secondaryButtonText: { color: colors.textMd },
  bindingBox: {
    gap: spacing.sm,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: colors.border,
    paddingTop: spacing.md,
  },
  bindingState: { color: colors.success, fontSize: 13, fontWeight: "700" },
  bindingOrigin: { color: colors.textLo, fontSize: 13, fontFamily: typography.mono },
  activity: { marginVertical: spacing.sm },
  footer: { color: colors.textLo, fontSize: 12, lineHeight: 18, textAlign: "center" },
});
