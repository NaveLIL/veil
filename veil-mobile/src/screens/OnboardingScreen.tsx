import React, { useEffect, useRef } from "react";
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
import {
  ChevronRight,
  Plus,
  RotateCcw,
  type LucideIcon,
} from "lucide-react-native";

import { PhaseShiftMark } from "../components/brand/PhaseShiftMark";
import { PublicFailureCard } from "../components/runtime/PublicFailureCard";
import { spacing } from "../lib/theme";
import { geometry, motion, type Palette } from "../interfacePreview/appearance";
import { useVeilStyles } from "../interfacePreview/useVeilStyles";
import { usePresentation } from "../interfacePreview/PresentationContext";
import { welcomeCopy as copy } from '../presentation/copy/welcome';
import {
  beginIdentitySetup,
  useIdentitySetupStore,
} from "../stores/identitySetup";

interface OnboardingScreenProps {
  reducedMotion: boolean;
}

export default function OnboardingScreen({
  reducedMotion,
}: OnboardingScreenProps) {
  const styles = useVeilStyles(createStyles);
  const activeMode = useIdentitySetupStore((state) => state.activeMode);
  const publicFailureCode = useIdentitySetupStore((state) => state.publicFailureCode);
  const recoveryNotice = useIdentitySetupStore((state) => state.recoveryNotice);
  const restartBlocked = useIdentitySetupStore((state) => state.restartBlocked);
  const entrance = useRef(new Animated.Value(reducedMotion ? 1 : 0)).current;

  useEffect(() => {
    if (reducedMotion) {
      entrance.setValue(1);
      return undefined;
    }

    const animation = Animated.timing(entrance, {
      toValue: 1,
      duration: motion.transitionDuration,
      easing: Easing.out(Easing.cubic),
      useNativeDriver: true,
    });
    animation.start();
    return () => {
      animation.stop();
    };
  }, [entrance, reducedMotion]);

  const busy = activeMode !== null;
  const setupDisabled = busy || restartBlocked;
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

      <SafeAreaView style={styles.safeArea} edges={["top", "bottom", "left", "right"]}>
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
              <View style={styles.markFrame}>
                <PhaseShiftMark
                  size={64}
                  label="Veil Phase Shift mark"
                  testID="brand-phase-shift-mark"
                />
              </View>
              <Text accessibilityRole="header" style={styles.brandName}>
                VEIL
              </Text>
              <Text style={styles.eyebrow}>{copy.eyebrow}</Text>
            </View>

            <View style={styles.heroCopy}>
              <Text accessibilityRole="header" style={styles.title}>
                {copy.title}
              </Text>
              <Text style={styles.subtitle}>
                {copy.description}
              </Text>
            </View>

            <View style={styles.assuranceRow} accessibilityRole="summary">
              <AssuranceItem label={copy.native} />
              <AssuranceItem label={copy.vault} />
              <AssuranceItem label={copy.recovery} />
            </View>

            <View style={styles.actionPanel}>
              <Text style={styles.panelTitle}>{copy.panel}</Text>
              <Text style={styles.panelBody}>
                {copy.confirmation}
              </Text>

              {publicFailureCode || recoveryNotice ? (
                <View
                  testID="identity-setup-error"
                  accessibilityRole="alert"
                  accessibilityLiveRegion="assertive"
                  style={styles.failureStack}
                >
                  {publicFailureCode ? (
                    <PublicFailureCard code={publicFailureCode} announce={false} />
                  ) : null}
                  {recoveryNotice ? (
                    <View
                      testID="identity-recovery-notice"
                      style={styles.recoveryBox}
                    >
                      <Text style={styles.recoveryLabel}>{copy.recoveryStatus}</Text>
                      <Text style={styles.recoveryText}>{recoveryNotice}</Text>
                    </View>
                  ) : null}
                </View>
              ) : null}

              <View style={styles.actions}>
                <SetupButton
                  testID="identity-setup-create"
                  title={copy.create}
                  description={copy.createDescription}
                  icon={Plus}
                  variant="primary"
                  loading={activeMode === "create"}
                  disabled={setupDisabled}
                  onPress={() => beginIdentitySetup("create")}
                />
                <SetupButton
                  testID="identity-setup-restore"
                  title={copy.restore}
                  description={copy.restoreDescription}
                  icon={RotateCcw}
                  variant="secondary"
                  loading={activeMode === "restore"}
                  disabled={setupDisabled}
                  onPress={() => beginIdentitySetup("restore")}
                />
              </View>

              {busy ? (
                <Text
                  testID="identity-setup-loading"
                  accessibilityLiveRegion="polite"
                  style={styles.loadingText}
                >
                  {copy.busy}
                </Text>
              ) : null}
            </View>

            <Text style={styles.footer}>
              {copy.footer}
            </Text>
          </Animated.View>
        </ScrollView>
      </SafeAreaView>
    </View>
  );
}

function AssuranceItem({ label }: { label: string }) {
  const styles = useVeilStyles(createStyles);
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
  icon: LucideIcon;
  variant: "primary" | "secondary";
  loading: boolean;
  disabled: boolean;
  onPress: () => void;
}

function SetupButton({
  testID,
  title,
  description,
  icon: Icon,
  variant,
  loading,
  disabled,
  onPress,
}: SetupButtonProps) {
  const { c } = usePresentation();
  const styles = useVeilStyles(createStyles);
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
          <ActivityIndicator size="small" color={primary ? "#ffffff" : c.accent} />
        ) : (
          <Icon size={22} strokeWidth={2.1} color={primary ? "#ffffff" : c.accent} />
        )}
      </View>
      <View style={styles.buttonCopy}>
        <Text style={[styles.buttonTitle, primary && styles.buttonTitlePrimary]}>{title}</Text>
        <Text style={[styles.buttonDescription, primary && styles.buttonDescriptionPrimary]}>
          {description}
        </Text>
      </View>
      <ChevronRight
        size={22}
        strokeWidth={2}
        color={primary ? "rgba(255,255,255,0.72)" : c.muted}
      />
    </Pressable>
  );
}

const createStyles = (c: Palette) => StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: c.bg,
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
    borderRadius: geometry.radius,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: c.surface,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.line,
    shadowColor: c.accent,
    shadowOpacity: 0.28,
    shadowRadius: 24,
    shadowOffset: { width: 0, height: 10 },
    elevation: 8,
  },
  brandName: {
    color: c.text,
    fontSize: 18,
    fontWeight: "800",
    letterSpacing: 7,
    marginTop: spacing.lg,
    marginLeft: 7,
  },
  eyebrow: {
    color: c.accent,
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
    color: c.text,
    fontSize: 30,
    lineHeight: 36,
    fontWeight: "800",
    textAlign: "center",
    letterSpacing: -0.5,
  },
  subtitle: {
    color: c.muted,
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
    borderRadius: 999,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.line,
    backgroundColor: c.raised,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
  },
  assuranceDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: c.accent,
  },
  assuranceText: {
    color: c.muted,
    fontSize: 12,
    fontWeight: "600",
  },
  actionPanel: {
    borderRadius: geometry.radius,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.line,
    backgroundColor: c.surface,
    padding: spacing.xl,
    marginTop: spacing.xxl,
    shadowColor: "#000000",
    shadowOpacity: 0.32,
    shadowRadius: 24,
    shadowOffset: { width: 0, height: 12 },
    elevation: 10,
  },
  panelTitle: {
    color: c.text,
    fontSize: 18,
    lineHeight: 24,
    fontWeight: "800",
  },
  panelBody: {
    color: c.muted,
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
    borderRadius: geometry.radius,
    borderWidth: StyleSheet.hairlineWidth,
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
  },
  setupButtonPrimary: {
    backgroundColor: c.accent,
    borderColor: "rgba(255,255,255,0.16)",
  },
  setupButtonSecondary: {
    backgroundColor: c.raised,
    borderColor: c.line,
  },
  setupButtonPressed: {
    opacity: 0.82,
    transform: [{ scale: 0.992 }],
  },
  setupButtonDisabled: { opacity: 0.46 },
  buttonMarker: {
    width: 44,
    height: 44,
    borderRadius: geometry.radius,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: c.tint,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: "rgba(167,139,250,0.24)",
  },
  buttonMarkerPrimary: {
    backgroundColor: "rgba(255,255,255,0.12)",
    borderColor: "rgba(255,255,255,0.20)",
  },
  buttonCopy: {
    flex: 1,
    marginLeft: spacing.md,
  },
  buttonTitle: {
    color: c.text,
    fontSize: 15,
    lineHeight: 20,
    fontWeight: "800",
  },
  buttonTitlePrimary: { color: "#ffffff" },
  buttonDescription: {
    color: c.muted,
    fontSize: 12,
    lineHeight: 17,
    marginTop: 2,
  },
  buttonDescriptionPrimary: { color: "rgba(255,255,255,0.74)" },
  failureStack: {
    gap: spacing.sm,
    marginTop: spacing.lg,
  },
  recoveryBox: {
    minHeight: 48,
    justifyContent: "center",
    borderRadius: geometry.radius,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.danger,
    backgroundColor: c.tint,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
  },
  recoveryLabel: {
    color: c.muted,
    fontSize: 9,
    fontWeight: "900",
    letterSpacing: 1.2,
    marginBottom: 4,
  },
  recoveryText: {
    color: c.danger,
    fontSize: 13,
    lineHeight: 19,
  },
  loadingText: {
    color: c.muted,
    fontSize: 12,
    lineHeight: 18,
    textAlign: "center",
    marginTop: spacing.md,
  },
  footer: {
    color: c.muted,
    fontSize: 11,
    lineHeight: 17,
    textAlign: "center",
    marginTop: spacing.xl,
    paddingHorizontal: spacing.lg,
  },
});
