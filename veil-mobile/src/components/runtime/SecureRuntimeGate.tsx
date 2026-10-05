import { runtimeCopy } from '../../presentation/copy/runtime';
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
import { spacing } from "../../lib/theme";
import { geometry, type Palette } from "../../interfacePreview/appearance";
import { useVeilStyles } from "../../interfacePreview/useVeilStyles";
import type { VeilMobileRuntimeSnapshot } from "../../native/runtime";
import {
  hasExactAuthenticatedBinding,
  type RuntimeOperation,
} from "../../stores/runtime";
import { usePresentation } from '../../interfacePreview/PresentationContext';

interface SecureRuntimeGateProps {
  snapshot: VeilMobileRuntimeSnapshot;
  requiresExplicitReopen: boolean;
  operation: RuntimeOperation;
  publicFailureCode: PublicFailureCodeV1 | null;
  reducedMotion: boolean;
  onUnlock: () => void;
  onConnect: (canonicalOrigin: string) => void;
  onImportAccessPass: () => void;
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
  onImportAccessPass,
  onUsePendingAccessPass,
  onDiscardPendingAccessPass,
  onRefresh,
}: SecureRuntimeGateProps) {
  const { c } = usePresentation();
  const styles = useVeilStyles(createStyles);
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
        title: runtimeCopy("Unlock required"),
        body: runtimeCopy("Veil locked this account when the app left the foreground. Reopen it explicitly to continue."),
      };
    }
    if (snapshot.sessionState === "locked" || snapshot.sessionState === "error") {
      return {
        title: runtimeCopy("Local account locked"),
        body: runtimeCopy("Your recovery material remains inside the encrypted native vault."),
      };
    }
    if (snapshot.sessionState === "opening" || snapshot.sessionState === "closing") {
      return {
        title: runtimeCopy("Securing local account"),
        body: runtimeCopy("Waiting for the native encrypted session to settle."),
      };
    }
    if (snapshot.connectionState === "connecting") {
      return {
        title: runtimeCopy("Authenticating Veil Node"),
        body: runtimeCopy("Establishing the native encrypted transport and account binding."),
      };
    }
    if (snapshot.connectionState === "connected" && !snapshot.directoryReady) {
      switch (snapshot.secureSyncState) {
        case "publishing_keys":
          return {
            title: runtimeCopy("Publishing device keys"),
            body: runtimeCopy("Preparing this device for authenticated encrypted conversations."),
          };
        case "syncing_directory":
          return {
            title: runtimeCopy("Verifying conversations"),
            body: runtimeCopy("Loading the authenticated conversation directory into encrypted local storage."),
          };
        case "syncing_history":
          return {
            title: runtimeCopy("Restoring encrypted history"),
            body: runtimeCopy("Validating and storing supported Direct messages before live chat can open."),
          };
        case "history_synchronized":
          return {
            title: runtimeCopy("Reconciling live messages"),
            body: runtimeCopy("History is synchronized. Veil is still waiting for safe live-message reconciliation."),
          };
        default:
          return {
            title: runtimeCopy("Secure sync is not ready"),
            body: runtimeCopy("The account is authenticated, but native secure synchronization is still incomplete."),
          };
      }
    }
    return {
      title: runtimeCopy("Connect to your Veil Node"),
      body: runtimeCopy("Only the canonical server origin crosses this UI boundary. Authentication remains native."),
    };
  }, [
    requiresExplicitReopen,
    snapshot.connectionState,
    snapshot.directoryReady,
    snapshot.secureSyncState,
    snapshot.sessionState,
  ]);

  const needsUnlock = requiresExplicitReopen || snapshot.sessionState !== "open";
  const canEnterOrigin = pending === null
    && !needsUnlock
    && (snapshot.connectionState === "disconnected" || snapshot.connectionState === "error");
  const bindingIsExact = hasExactAuthenticatedBinding(snapshot.binding);
  const canImportPass = pending === null
    && snapshot.sessionState !== "opening"
    && snapshot.sessionState !== "closing"
    && (snapshot.connectionState === "disconnected" || snapshot.connectionState === "error");

  return (
    <SafeAreaView testID="secure-runtime-gate" style={[styles.root, {backgroundColor:c.bg}]} edges={["top", "bottom", "left", "right"]}>
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
            <Text style={styles.brandSub}>{runtimeCopy("Native secure session")}</Text>
          </View>

          {pending ? (
            <View testID="access-pass-review" style={[styles.card, styles.passCard]}>
              <View style={styles.cardHeader}>
                <View style={styles.statusDot} />
                <Text style={styles.eyebrow}>{runtimeCopy("NODE ACCESS PASS")}</Text>
              </View>
              <Text style={styles.cardTitle}>{runtimeCopy("Review invitation")}</Text>
              <Text style={styles.cardBody}>{runtimeCopy("This pass can register one account. Its bearer never enters JavaScript.")}</Text>
              <MetadataRow label={runtimeCopy("Origin")} value={pending.canonicalOrigin} testID="access-pass-origin" />
              <MetadataRow label={runtimeCopy("Reference")} value={pending.tokenRef} mono testID="access-pass-reference" />
              <MetadataRow label={runtimeCopy("Expires in")} value={formatTtl(pending.expiresInSeconds)} testID="access-pass-ttl" />
              <View style={styles.actionStack}>
                <ActionButton
                  testID="use-access-pass"
                  label={operation === "using_access_pass" ? runtimeCopy("Opening securely...") : runtimeCopy("Use access pass")}
                  onPress={() => onUsePendingAccessPass(pending.flowId)}
                  disabled={busy}
                  primary
                />
                <ActionButton
                  testID="discard-access-pass"
                  label={runtimeCopy("Discard invitation")}
                  onPress={() => onDiscardPendingAccessPass(pending.flowId)}
                  disabled={busy}
                />
              </View>
            </View>
          ) : null}

          {canImportPass ? (
            <View style={styles.card}>
              <Text accessibilityRole="header" style={styles.cardTitle}>{runtimeCopy("Have a Node invitation?")}</Text>
              <Text style={styles.cardBody}>{runtimeCopy("Copy the HTTPS invitation link from your Node, then import it here to review the origin before registration.")}</Text>
              <ActionButton
                testID="import-access-pass"
                label={operation === "importing_access_pass" ? runtimeCopy("Importing securely...") : runtimeCopy("Import invitation from clipboard")}
                onPress={onImportAccessPass}
                disabled={busy}
              />
              <Text style={styles.cardBody}>{runtimeCopy("The link stays in the clipboard until you replace or clear it.")}</Text>
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
                label={operation === "unlocking" ? runtimeCopy("Unlocking...") : runtimeCopy("Unlock local account")}
                onPress={onUnlock}
                disabled={busy || snapshot.sessionState === "opening" || snapshot.sessionState === "closing"}
                primary
              />
            ) : null}

            {canEnterOrigin ? (
              <View style={styles.form}>
                <Text style={styles.inputLabel}>{runtimeCopy("Canonical Veil Node origin")}</Text>
                <TextInput
                  testID="node-origin-input"
                  accessibilityLabel={runtimeCopy("Canonical Veil Node origin")}
                  value={origin}
                  onChangeText={setOrigin}
                  autoCapitalize="none"
                  autoCorrect={false}
                  spellCheck={false}
                  keyboardType="url"
                  textContentType="URL"
                  placeholder="https://veil.example"
                  placeholderTextColor={c.muted}
                  style={styles.input}
                />
                <ActionButton
                  testID="connect-node"
                  label={operation === "connecting" ? runtimeCopy("Connecting...") : runtimeCopy("Connect securely")}
                  onPress={() => onConnect(origin)}
                  disabled={busy || !origin.trim()}
                  primary
                />
              </View>
            ) : null}

            {!needsUnlock && snapshot.connectionState === "connected" ? (
              <View style={styles.bindingBox}>
                <Text style={styles.bindingState}>
                  {bindingIsExact ? runtimeCopy("Authenticated binding verified") : runtimeCopy("Binding verification unavailable")}
                </Text>
                {snapshot.binding ? (
                  <Text style={styles.bindingOrigin}>{snapshot.binding.canonicalServerOrigin}</Text>
                ) : null}
                <ActionButton
                  testID="refresh-runtime"
                  label={operation === "refreshing" ? runtimeCopy("Refreshing...") : runtimeCopy("Refresh secure state")}
                  onPress={onRefresh}
                  disabled={busy}
                />
              </View>
            ) : null}

            {!reducedMotion && busy && operation !== "unlocking" && operation !== "connecting" ? (
              <ActivityIndicator
                accessibilityLabel={runtimeCopy("Secure action in progress")}
                color={c.accent}
                style={styles.activity}
              />
            ) : null}
          </View>

          <Text style={styles.footer}>{runtimeCopy("Messages stay hidden until the native session, exact account binding, and verified directory are all ready.")}</Text>
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
  const styles = useVeilStyles(createStyles);
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
  const styles = useVeilStyles(createStyles);
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

const createStyles = (c: Palette) => StyleSheet.create({
  root: { flex: 1, backgroundColor: c.bg },
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
    color: c.text,
    fontSize: 17,
    fontWeight: "800",
    letterSpacing: 5,
    marginTop: spacing.md,
  },
  brandSub: { color: c.muted, fontSize: 13, marginTop: spacing.xs },
  card: {
    backgroundColor: c.surface,
    borderRadius: geometry.radius,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.line,
    padding: spacing.xl,
    gap: spacing.md,
  },
  passCard: { borderColor: c.accent },
  cardHeader: { flexDirection: "row", alignItems: "center", gap: spacing.sm },
  statusDot: { width: 8, height: 8, borderRadius: 4, backgroundColor: c.accent },
  eyebrow: { color: c.accent, fontSize: 11, fontWeight: "800", letterSpacing: 1.4 },
  cardTitle: { color: c.text, fontSize: 21, lineHeight: 27, fontWeight: "800" },
  cardBody: { color: c.text, fontSize: 15, lineHeight: 22 },
  metadataRow: {
    minHeight: 48,
    justifyContent: "center",
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: c.line,
    paddingVertical: spacing.sm,
  },
  metadataLabel: { color: c.muted, fontSize: 12, fontWeight: "700", marginBottom: 4 },
  metadataValue: { color: c.text, fontSize: 14, lineHeight: 20 },
  mono: { fontFamily: "monospace", letterSpacing: 1 },
  actionStack: { gap: spacing.sm, marginTop: spacing.xs },
  form: { gap: spacing.sm, marginTop: spacing.xs },
  inputLabel: { color: c.text, fontSize: 13, fontWeight: "700" },
  input: {
    minHeight: 52,
    borderRadius: geometry.radius,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.line,
    backgroundColor: c.surface,
    color: c.text,
    fontSize: 16,
    paddingHorizontal: spacing.lg,
  },
  button: {
    minHeight: 48,
    borderRadius: geometry.radius,
    alignItems: "center",
    justifyContent: "center",
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
  },
  primaryButton: { backgroundColor: c.accent },
  secondaryButton: {
    backgroundColor: c.surface,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.line,
  },
  buttonPressed: { opacity: 0.78 },
  buttonDisabled: { opacity: 0.46 },
  buttonText: { color: "#fff", fontSize: 15, fontWeight: "800", textAlign: "center" },
  secondaryButtonText: { color: c.text },
  bindingBox: {
    gap: spacing.sm,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: c.line,
    paddingTop: spacing.md,
  },
  bindingState: { color: c.accent, fontSize: 13, fontWeight: "700" },
  bindingOrigin: { color: c.muted, fontSize: 13, fontFamily: "monospace" },
  activity: { marginVertical: spacing.sm },
  footer: { color: c.muted, fontSize: 12, lineHeight: 18, textAlign: "center" },
});
