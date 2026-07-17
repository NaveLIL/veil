import React, { useEffect, useRef, useState } from "react";
import {
  ActivityIndicator,
  Animated,
  Easing,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { LinearGradient } from "expo-linear-gradient";
import { SafeAreaView } from "react-native-safe-area-context";
import Svg, { Path, Rect } from "react-native-svg";

import { colors, radii, spacing } from "../lib/theme";
import {
  beginNativeIdentitySetup,
  type NativeIdentitySetupMode,
} from "../native/identitySetup";

interface OnboardingScreenProps {
  onCommitted: () => void | Promise<void>;
  reducedMotion: boolean;
}

const PUBLIC_SETUP_ERROR =
  "Secure setup could not be completed. Nothing changed. Please try again.";
const PUBLIC_REFRESH_ERROR =
  "Identity setup finished, but secure status could not be refreshed. Close Veil and reopen it.";

export default function OnboardingScreen({
  onCommitted,
  reducedMotion,
}: OnboardingScreenProps) {
  const [activeMode, setActiveMode] = useState<NativeIdentitySetupMode | null>(null);
  const [publicError, setPublicError] = useState<string | null>(null);
  const mounted = useRef(true);
  const entrance = useRef(new Animated.Value(reducedMotion ? 1 : 0)).current;

  useEffect(() => {
    mounted.current = true;
    if (reducedMotion) {
      entrance.setValue(1);
      return () => {
        mounted.current = false;
      };
    }

    const animation = Animated.timing(entrance, {
      toValue: 1,
      duration: 320,
      easing: Easing.out(Easing.cubic),
      useNativeDriver: true,
    });
    animation.start();
    return () => {
      mounted.current = false;
      animation.stop();
    };
  }, [entrance, reducedMotion]);

  const beginSetup = async (mode: NativeIdentitySetupMode): Promise<void> => {
    if (activeMode) return;
    setPublicError(null);
    setActiveMode(mode);

    let result: "committed" | "cancelled";
    try {
      result = await beginNativeIdentitySetup(mode);
    } catch {
      if (mounted.current) setPublicError(PUBLIC_SETUP_ERROR);
      if (mounted.current) setActiveMode(null);
      return;
    }

    if (!mounted.current || result === "cancelled") {
      if (mounted.current) setActiveMode(null);
      return;
    }

    try {
      await onCommitted();
    } catch {
      if (mounted.current) setPublicError(PUBLIC_REFRESH_ERROR);
    } finally {
      if (mounted.current) setActiveMode(null);
    }
  };

  const busy = activeMode !== null;
  const animatedStyle = reducedMotion
    ? undefined
    : {
        opacity: entrance,
        transform: [
          {
            translateY: entrance.interpolate({
              inputRange: [0, 1],
              outputRange: [12, 0],
            }),
          },
        ],
      };

  return (
    <View testID="native-identity-welcome" style={styles.root}>
      <LinearGradient
        pointerEvents="none"
        colors={["rgba(124,107,245,0.20)", "rgba(17,17,23,0)"]}
        start={{ x: 0.1, y: 0 }}
        end={{ x: 0.72, y: 0.6 }}
        style={styles.ambientTop}
      />
      <View pointerEvents="none" style={styles.ambientOrb} />

      <SafeAreaView style={styles.safeArea} edges={["top", "bottom"]}>
        <ScrollView
          contentContainerStyle={styles.scrollContent}
          showsVerticalScrollIndicator={false}
          alwaysBounceVertical={false}
        >
          <Animated.View
            accessibilityState={{ busy }}
            style={[styles.content, animatedStyle]}
          >
            <View style={styles.brandBlock}>
              <PhaseShiftMark />
              <Text accessibilityRole="header" style={styles.brandName}>
                VEIL
              </Text>
              <Text style={styles.eyebrow}>PRIVATE MOBILE PREVIEW</Text>
            </View>

            <View style={styles.heroCopy}>
              <Text accessibilityRole="header" style={styles.title}>
                Your identity stays native.
              </Text>
              <Text style={styles.subtitle}>
                Create or restore inside a protected system screen. Recovery material never enters
                the React Native interface.
              </Text>
            </View>

            <View style={styles.assuranceRow} accessibilityRole="summary">
              <AssuranceItem label="Native-only setup" />
              <AssuranceItem label="Encrypted local vault" />
              <AssuranceItem label="No cloud recovery" />
            </View>

            <View style={styles.actionPanel}>
              <Text style={styles.panelTitle}>Set up this device</Text>
              <Text style={styles.panelBody}>
                Nothing is saved until you confirm in the protected native flow. You can cancel at
                any time.
              </Text>

              {publicError ? (
                <View
                  testID="identity-setup-error"
                  accessibilityRole="alert"
                  accessibilityLiveRegion="assertive"
                  style={styles.errorBox}
                >
                  <Text style={styles.errorText}>{publicError}</Text>
                </View>
              ) : null}

              <View style={styles.actions}>
                <SetupButton
                  testID="identity-setup-create"
                  title="Create identity"
                  description="Start with a new device-local identity"
                  marker="+"
                  variant="primary"
                  loading={activeMode === "create"}
                  disabled={busy}
                  onPress={() => void beginSetup("create")}
                />
                <SetupButton
                  testID="identity-setup-restore"
                  title="Restore identity"
                  description="Recover an identity you already control"
                  marker="↙"
                  variant="secondary"
                  loading={activeMode === "restore"}
                  disabled={busy}
                  onPress={() => void beginSetup("restore")}
                />
              </View>

              {busy ? (
                <Text
                  testID="identity-setup-loading"
                  accessibilityLiveRegion="polite"
                  style={styles.loadingText}
                >
                  Protected setup is open…
                </Text>
              ) : null}
            </View>

            <Text style={styles.footer}>
              Development preview · Some mobile features are not available yet.
            </Text>
          </Animated.View>
        </ScrollView>
      </SafeAreaView>
    </View>
  );
}

function PhaseShiftMark() {
  return (
    <View style={styles.markFrame}>
      <Svg
        testID="brand-phase-shift-mark"
        accessibilityRole="image"
        accessibilityLabel="Veil Phase Shift mark"
        width={64}
        height={64}
        viewBox="0 0 24 24"
      >
        {/* Exact geometry and colors from assets/brand/phase-shift-mark.svg. */}
        <Rect x="0.5" y="0.5" width="23" height="23" rx="5.5" fill="#0d0e14" stroke="#2e2e50" />
        <Path
          fill="#a78bfa"
          d="M4 4H8V11.8L4 13ZM4 16L8 14.8V20H4ZM10 2H14V10.5L10 11.7ZM10 14.7L14 13.5V22H10ZM16 5H20V8.2L16 9.4ZM16 12.4L20 11.2V19H16Z"
        />
      </Svg>
    </View>
  );
}

function AssuranceItem({ label }: { label: string }) {
  return (
    <View style={styles.assuranceItem}>
      <View style={styles.assuranceDot} />
      <Text style={styles.assuranceText}>{label}</Text>
    </View>
  );
}

interface SetupButtonProps {
  testID: string;
  title: string;
  description: string;
  marker: string;
  variant: "primary" | "secondary";
  loading: boolean;
  disabled: boolean;
  onPress: () => void;
}

function SetupButton({
  testID,
  title,
  description,
  marker,
  variant,
  loading,
  disabled,
  onPress,
}: SetupButtonProps) {
  const primary = variant === "primary";
  return (
    <Pressable
      testID={testID}
      accessibilityRole="button"
      accessibilityLabel={title}
      accessibilityHint={description}
      accessibilityState={{ disabled, busy: loading }}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }) => [
        styles.setupButton,
        primary ? styles.setupButtonPrimary : styles.setupButtonSecondary,
        pressed && !disabled ? styles.setupButtonPressed : null,
        disabled && !loading ? styles.setupButtonDisabled : null,
      ]}
    >
      <View style={[styles.buttonMarker, primary && styles.buttonMarkerPrimary]}>
        {loading ? (
          <ActivityIndicator size="small" color={primary ? "#ffffff" : colors.primaryHi} />
        ) : (
          <Text style={[styles.buttonMarkerText, primary && styles.buttonMarkerTextPrimary]}>
            {marker}
          </Text>
        )}
      </View>
      <View style={styles.buttonCopy}>
        <Text style={[styles.buttonTitle, primary && styles.buttonTitlePrimary]}>{title}</Text>
        <Text style={[styles.buttonDescription, primary && styles.buttonDescriptionPrimary]}>
          {description}
        </Text>
      </View>
      <Text importantForAccessibility="no" style={[styles.chevron, primary && styles.chevronPrimary]}>
        ›
      </Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: colors.background,
  },
  safeArea: { flex: 1 },
  ambientTop: {
    position: "absolute",
    top: 0,
    left: 0,
    right: 0,
    height: "54%",
  },
  ambientOrb: {
    position: "absolute",
    width: 260,
    height: 260,
    borderRadius: 130,
    right: -150,
    bottom: 32,
    backgroundColor: "rgba(83,72,180,0.10)",
  },
  scrollContent: {
    flexGrow: 1,
    justifyContent: "center",
    paddingHorizontal: spacing.xl,
    paddingVertical: spacing.xxl,
  },
  content: {
    width: "100%",
    maxWidth: 520,
    alignSelf: "center",
  },
  brandBlock: {
    alignItems: "center",
  },
  markFrame: {
    width: 76,
    height: 76,
    borderRadius: radii.xl,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(13,14,20,0.78)",
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: "rgba(167,139,250,0.24)",
    shadowColor: colors.primary,
    shadowOpacity: 0.28,
    shadowRadius: 24,
    shadowOffset: { width: 0, height: 10 },
    elevation: 8,
  },
  brandName: {
    color: colors.textHi,
    fontSize: 18,
    fontWeight: "800",
    letterSpacing: 7,
    marginTop: spacing.lg,
    marginLeft: 7,
  },
  eyebrow: {
    color: colors.primaryHi,
    fontSize: 11,
    fontWeight: "700",
    letterSpacing: 1.5,
    marginTop: spacing.sm,
  },
  heroCopy: {
    alignItems: "center",
    marginTop: spacing.xxl,
  },
  title: {
    color: colors.textHi,
    fontSize: 30,
    lineHeight: 36,
    fontWeight: "800",
    textAlign: "center",
    letterSpacing: -0.5,
  },
  subtitle: {
    color: colors.textMd,
    fontSize: 16,
    lineHeight: 24,
    textAlign: "center",
    marginTop: spacing.md,
    maxWidth: 450,
  },
  assuranceRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    justifyContent: "center",
    gap: spacing.sm,
    marginTop: spacing.xl,
  },
  assuranceItem: {
    minHeight: 36,
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    borderRadius: radii.pill,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    backgroundColor: colors.surfaceLow,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
  },
  assuranceDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: colors.success,
  },
  assuranceText: {
    color: colors.textMd,
    fontSize: 12,
    fontWeight: "600",
  },
  actionPanel: {
    borderRadius: radii.xl,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    backgroundColor: colors.surfaceSolid,
    padding: spacing.xl,
    marginTop: spacing.xxl,
    shadowColor: "#000000",
    shadowOpacity: 0.32,
    shadowRadius: 24,
    shadowOffset: { width: 0, height: 12 },
    elevation: 10,
  },
  panelTitle: {
    color: colors.textHi,
    fontSize: 18,
    lineHeight: 24,
    fontWeight: "800",
  },
  panelBody: {
    color: colors.textMd,
    fontSize: 14,
    lineHeight: 21,
    marginTop: spacing.xs,
  },
  actions: {
    gap: spacing.md,
    marginTop: spacing.xl,
  },
  setupButton: {
    minHeight: 72,
    borderRadius: radii.lg,
    borderWidth: StyleSheet.hairlineWidth,
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
  },
  setupButtonPrimary: {
    backgroundColor: colors.primaryDeep,
    borderColor: "rgba(255,255,255,0.16)",
  },
  setupButtonSecondary: {
    backgroundColor: colors.surfaceLow,
    borderColor: colors.border,
  },
  setupButtonPressed: {
    opacity: 0.82,
    transform: [{ scale: 0.992 }],
  },
  setupButtonDisabled: { opacity: 0.46 },
  buttonMarker: {
    width: 44,
    height: 44,
    borderRadius: 14,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(167,139,250,0.10)",
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: "rgba(167,139,250,0.24)",
  },
  buttonMarkerPrimary: {
    backgroundColor: "rgba(255,255,255,0.12)",
    borderColor: "rgba(255,255,255,0.20)",
  },
  buttonMarkerText: {
    color: colors.primaryHi,
    fontSize: 24,
    lineHeight: 28,
    fontWeight: "500",
  },
  buttonMarkerTextPrimary: { color: "#ffffff" },
  buttonCopy: {
    flex: 1,
    marginLeft: spacing.md,
  },
  buttonTitle: {
    color: colors.textHi,
    fontSize: 15,
    lineHeight: 20,
    fontWeight: "800",
  },
  buttonTitlePrimary: { color: "#ffffff" },
  buttonDescription: {
    color: colors.textMd,
    fontSize: 12,
    lineHeight: 17,
    marginTop: 2,
  },
  buttonDescriptionPrimary: { color: "rgba(255,255,255,0.74)" },
  chevron: {
    color: colors.textLo,
    fontSize: 28,
    lineHeight: 32,
    marginLeft: spacing.sm,
  },
  chevronPrimary: { color: "rgba(255,255,255,0.72)" },
  errorBox: {
    minHeight: 48,
    justifyContent: "center",
    borderRadius: radii.md,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.destructiveBorder,
    backgroundColor: colors.destructiveBg,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    marginTop: spacing.lg,
  },
  errorText: {
    color: colors.destructive,
    fontSize: 13,
    lineHeight: 19,
  },
  loadingText: {
    color: colors.textLo,
    fontSize: 12,
    lineHeight: 18,
    textAlign: "center",
    marginTop: spacing.md,
  },
  footer: {
    color: colors.textLo,
    fontSize: 11,
    lineHeight: 17,
    textAlign: "center",
    marginTop: spacing.xl,
    paddingHorizontal: spacing.lg,
  },
});
