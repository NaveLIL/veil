import React, { useEffect, useRef, useState } from "react";
import {
  Animated,
  Easing,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  useWindowDimensions,
  View,
} from "react-native";
import { LinearGradient } from "expo-linear-gradient";
import * as Clipboard from "expo-clipboard";
import { SafeAreaView } from "react-native-safe-area-context";

import { colors, motion, radii, spacing } from "../lib/theme";
import { Island } from "../components/ui/Island";
import { IslandButton } from "../components/ui/IslandButton";
import { HebrewRain } from "../components/onboarding/HebrewRain";
import { GlowBlobs } from "../components/onboarding/GlowBlobs";
import { TaglineCarousel } from "../components/onboarding/TaglineCarousel";
import VeilCrypto from "../native/crypto";
import { useAuthStore } from "../stores/auth";

type Step = "welcome" | "generate" | "restore";

export default function OnboardingScreen() {
  const { height } = useWindowDimensions();
  const [step, setStep] = useState<Step>("welcome");
  const [mnemonic, setMnemonic] = useState("");
  const [restoreInput, setRestoreInput] = useState("");
  const [showPhrase, setShowPhrase] = useState(true);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const { setIdentityKey } = useAuthStore();

  // Step transition: opacity + translateY + scale.
  const t = useRef(new Animated.Value(1)).current;

  const animateStep = (next: Step) => {
    setError("");
    Animated.timing(t, {
      toValue: 0,
      duration: motion.leaveMs,
      easing: Easing.in(Easing.cubic),
      useNativeDriver: true,
    }).start(() => {
      setStep(next);
      // Start from below for entry.
      t.setValue(-1);
      Animated.timing(t, {
        toValue: 1,
        duration: motion.enterMs,
        easing: Easing.out(Easing.cubic),
        useNativeDriver: true,
      }).start();
    });
  };

  const enterStyle = {
    opacity: t.interpolate({
      inputRange: [-1, 0, 1],
      outputRange: [0, 0, 1],
    }),
    transform: [
      {
        translateY: t.interpolate({
          inputRange: [-1, 0, 1],
          outputRange: [-24, 24, 0],
        }),
      },
      {
        scale: t.interpolate({
          inputRange: [-1, 0, 1],
          outputRange: [0.97, 0.97, 1],
        }),
      },
    ],
  };

  // Error toast slide-in from top.
  const errorAnim = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.timing(errorAnim, {
      toValue: error ? 1 : 0,
      duration: 220,
      easing: Easing.out(Easing.cubic),
      useNativeDriver: true,
    }).start();
  }, [error, errorAnim]);

  const generateMnemonic = async () => {
    try {
      setError("");
      setLoading(true);
      const m = await VeilCrypto.generateMnemonic();
      setMnemonic(m);
      animateStep("generate");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async () => {
    await Clipboard.setStringAsync(mnemonic);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const initIdentity = async (phrase: string) => {
    try {
      setLoading(true);
      setError("");
      const normalized = phrase.trim().replace(/\s+/g, " ");
      if (!normalized) {
        setError("Recovery phrase is empty.");
        return;
      }
      const ok = await VeilCrypto.validateMnemonic(normalized);
      if (!ok) {
        setError("Invalid recovery phrase. Check spelling and order.");
        return;
      }
      const key = await VeilCrypto.createIdentity(normalized);
      // Clear sensitive state only after successful init.
      setMnemonic("");
      setRestoreInput("");
      setIdentityKey(key);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const words = mnemonic.split(" ").filter(Boolean);

  return (
    <View style={styles.root}>
      <GlowBlobs />
      <HebrewRain height={height} />

      <SafeAreaView style={styles.safe} edges={["top", "bottom"]}>
        <KeyboardAvoidingView
          style={styles.flex}
          behavior={Platform.OS === "ios" ? "padding" : undefined}
        >
          {/* Error toast */}
          <Animated.View
            pointerEvents={error ? "auto" : "none"}
            style={[
              styles.errorWrap,
              {
                opacity: errorAnim,
                transform: [
                  {
                    translateY: errorAnim.interpolate({
                      inputRange: [0, 1],
                      outputRange: [-20, 0],
                    }),
                  },
                ],
              },
            ]}
          >
            <View style={styles.errorBox}>
              <Text style={styles.errorIcon}>⚠</Text>
              <Text style={styles.errorText} numberOfLines={3}>
                {error}
              </Text>
            </View>
          </Animated.View>

          <Animated.View style={[styles.stage, enterStyle]}>
            {step === "welcome" ? (
              <WelcomeStep
                onCreate={generateMnemonic}
                onRestore={() => animateStep("restore")}
                loading={loading}
              />
            ) : null}

            {step === "generate" ? (
              <GenerateStep
                words={words}
                showPhrase={showPhrase}
                onToggleVisibility={() => setShowPhrase((v) => !v)}
                copied={copied}
                onCopy={copyToClipboard}
                onContinue={() => initIdentity(mnemonic)}
                onBack={() => animateStep("welcome")}
                loading={loading}
              />
            ) : null}

            {step === "restore" ? (
              <RestoreStep
                value={restoreInput}
                onChange={setRestoreInput}
                onContinue={() => initIdentity(restoreInput)}
                onBack={() => animateStep("welcome")}
                loading={loading}
              />
            ) : null}
          </Animated.View>
        </KeyboardAvoidingView>
      </SafeAreaView>
    </View>
  );
}

/* ─── Welcome ───────────────────────────────────────── */

const WelcomeStep: React.FC<{
  onCreate: () => void;
  onRestore: () => void;
  loading: boolean;
}> = ({ onCreate, onRestore, loading }) => (
  <View style={styles.welcomeStack}>
    <View style={styles.logoWrap}>
      <View style={styles.logoBadge}>
        <View style={styles.logoGlow} />
        <Text style={styles.logoMark}>◇</Text>
      </View>
      <Text style={styles.brand}>VEIL</Text>
      <Text style={styles.brandSub}>Encrypted messenger</Text>
    </View>

    <Island padding={spacing.xxl} style={styles.welcomeIsland}>
      <TaglineCarousel />

      <View style={styles.divider} />

      <View style={{ gap: spacing.md }}>
        <IslandButton
          label="Create New Key"
          onPress={onCreate}
          loading={loading}
          icon={<Text style={styles.btnIconText}>✦</Text>}
        />
        <IslandButton
          label="Restore from Phrase"
          onPress={onRestore}
          variant="secondary"
          icon={<Text style={[styles.btnIconText, { color: colors.textMd }]}>↓</Text>}
        />
      </View>
    </Island>
  </View>
);

/* ─── Generate ──────────────────────────────────────── */

const GenerateStep: React.FC<{
  words: string[];
  showPhrase: boolean;
  onToggleVisibility: () => void;
  copied: boolean;
  onCopy: () => void;
  onContinue: () => void;
  onBack: () => void;
  loading: boolean;
}> = ({ words, showPhrase, onToggleVisibility, copied, onCopy, onContinue, onBack, loading }) => (
  <ScrollView
    contentContainerStyle={styles.scrollPad}
    showsVerticalScrollIndicator={false}
  >
    <Island padding={spacing.xxl}>
      <Text style={styles.sectionTitle}>Recovery Phrase</Text>
      <Text style={styles.sectionSub}>
        Write down these 12 words in order. They are your only backup.
      </Text>

      <View style={styles.wordGrid}>
        {words.map((w, i) => (
          <View key={i} style={styles.wordCell}>
            <Text style={styles.wordNum}>{String(i + 1).padStart(2, "0")}</Text>
            <Text
              style={[
                styles.wordText,
                !showPhrase && { color: "transparent", textShadowColor: colors.textMd, textShadowRadius: 8 },
              ]}
            >
              {w}
            </Text>
          </View>
        ))}
      </View>

      <View style={styles.warningBox}>
        <Text style={styles.warningIcon}>⚠</Text>
        <Text style={styles.warningText}>
          Anyone with this phrase can read all your messages. Store it offline.
        </Text>
      </View>

      <View style={styles.row}>
        <Pressable
          style={[styles.smallBtn, copied ? styles.smallBtnSuccess : null]}
          onPress={onCopy}
          android_ripple={{ color: "rgba(255,255,255,0.08)" }}
        >
          <Text style={[styles.smallBtnText, copied ? { color: colors.success } : null]}>
            {copied ? "✓ Copied" : "Copy"}
          </Text>
        </Pressable>
        <Pressable
          style={styles.smallBtn}
          onPress={onToggleVisibility}
          android_ripple={{ color: "rgba(255,255,255,0.08)" }}
        >
          <Text style={styles.smallBtnText}>{showPhrase ? "Hide" : "Reveal"}</Text>
        </Pressable>
      </View>

      <View style={{ height: spacing.lg }} />

      <IslandButton
        label="I've saved my phrase"
        onPress={onContinue}
        loading={loading}
      />
      <Pressable onPress={onBack} style={styles.backBtn}>
        <Text style={styles.backText}>← Back</Text>
      </Pressable>
    </Island>
  </ScrollView>
);

/* ─── Restore ───────────────────────────────────────── */

const RestoreStep: React.FC<{
  value: string;
  onChange: (v: string) => void;
  onContinue: () => void;
  onBack: () => void;
  loading: boolean;
}> = ({ value, onChange, onContinue, onBack, loading }) => (
  <ScrollView
    contentContainerStyle={styles.scrollPad}
    showsVerticalScrollIndicator={false}
    keyboardShouldPersistTaps="handled"
  >
    <Island padding={spacing.xxl}>
      <Text style={styles.sectionTitle}>Restore Identity</Text>
      <Text style={styles.sectionSub}>
        Enter your 12-word recovery phrase to restore your identity on this device.
      </Text>

      <TextInput
        style={styles.textarea}
        value={value}
        onChangeText={onChange}
        placeholder="word1 word2 word3 …"
        placeholderTextColor={colors.textXLo}
        multiline
        autoCapitalize="none"
        autoCorrect={false}
        spellCheck={false}
        textAlignVertical="top"
      />

      <View style={{ height: spacing.lg }} />

      <IslandButton
        label="Restore Identity"
        onPress={onContinue}
        loading={loading}
        disabled={!value.trim()}
      />
      <Pressable onPress={onBack} style={styles.backBtn}>
        <Text style={styles.backText}>← Back</Text>
      </Pressable>
    </Island>
  </ScrollView>
);

/* ─── Styles ────────────────────────────────────────── */

const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: "#111117",
  },
  safe: { flex: 1 },
  flex: { flex: 1 },
  stage: {
    flex: 1,
    paddingHorizontal: spacing.xl,
    justifyContent: "flex-end",
    paddingBottom: spacing.xl,
  },
  scrollPad: {
    flexGrow: 1,
    justifyContent: "center",
    paddingVertical: spacing.xl,
  },

  // Welcome
  welcomeStack: { gap: spacing.xxl },
  logoWrap: {
    alignItems: "center",
    gap: 6,
  },
  logoBadge: {
    width: 64,
    height: 64,
    borderRadius: radii.lg + 2,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(124,107,245,0.18)",
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: "rgba(124,107,245,0.35)",
    overflow: "hidden",
  },
  logoGlow: {
    position: "absolute",
    inset: -16,
    backgroundColor: "rgba(124,107,245,0.18)",
    borderRadius: 32,
  } as any,
  logoMark: {
    color: colors.primaryHi,
    fontSize: 28,
  },
  brand: {
    fontSize: 18,
    fontWeight: "700",
    color: colors.textHi,
    letterSpacing: 6,
    marginTop: 6,
  },
  brandSub: {
    fontSize: 11,
    color: colors.textLo,
    letterSpacing: 1,
  },
  welcomeIsland: { gap: spacing.xl },
  divider: {
    height: StyleSheet.hairlineWidth,
    backgroundColor: colors.border,
    marginVertical: spacing.sm,
  },

  // Buttons
  btnIconText: {
    color: "#fff",
    fontSize: 16,
    fontWeight: "700",
  },

  // Generate / restore
  sectionTitle: {
    fontSize: 19,
    fontWeight: "700",
    color: colors.textHi,
    marginBottom: 6,
  },
  sectionSub: {
    fontSize: 13,
    color: colors.textLo,
    lineHeight: 19,
    marginBottom: spacing.lg,
  },
  wordGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
    marginBottom: spacing.lg,
  },
  wordCell: {
    width: "48%",
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: radii.md,
    backgroundColor: "rgba(255,255,255,0.03)",
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.borderSoft,
  },
  wordNum: {
    fontFamily: "monospace",
    fontSize: 11,
    color: colors.textXLo,
    width: 18,
    textAlign: "right",
  },
  wordText: {
    fontFamily: "monospace",
    fontSize: 14,
    color: colors.textHi,
    fontWeight: "500",
  },
  warningBox: {
    flexDirection: "row",
    gap: 10,
    padding: 14,
    borderRadius: radii.md,
    backgroundColor: colors.warningBg,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.warningBorder,
    marginBottom: spacing.lg,
  },
  warningIcon: { color: colors.warning, fontSize: 14 },
  warningText: { color: colors.warning, fontSize: 12, flex: 1, lineHeight: 17 },

  row: {
    flexDirection: "row",
    gap: spacing.md,
  },
  smallBtn: {
    flex: 1,
    height: 38,
    borderRadius: radii.md,
    backgroundColor: "rgba(255,255,255,0.04)",
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    alignItems: "center",
    justifyContent: "center",
    overflow: "hidden",
  },
  smallBtnSuccess: {
    backgroundColor: colors.successBg,
    borderColor: colors.successBorder,
  },
  smallBtnText: {
    fontSize: 12,
    fontWeight: "600",
    color: colors.textMd,
  },

  textarea: {
    minHeight: 140,
    backgroundColor: "rgba(255,255,255,0.04)",
    borderRadius: radii.lg,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    color: colors.textHi,
    fontFamily: "monospace",
    fontSize: 15,
    lineHeight: 24,
    padding: spacing.lg,
  },

  backBtn: {
    height: 40,
    alignItems: "center",
    justifyContent: "center",
    marginTop: 4,
  },
  backText: {
    color: colors.textLo,
    fontSize: 13,
  },

  // Error toast
  errorWrap: {
    position: "absolute",
    top: spacing.lg,
    left: spacing.lg,
    right: spacing.lg,
    zIndex: 10,
  },
  errorBox: {
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
    padding: 12,
    paddingHorizontal: 14,
    borderRadius: radii.md,
    backgroundColor: colors.destructiveBg,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.destructiveBorder,
  },
  errorIcon: { color: colors.destructive, fontSize: 14 },
  errorText: { color: colors.destructive, fontSize: 12, flex: 1, lineHeight: 17 },
});

// LinearGradient is imported because TaglineCarousel/IslandButton use it indirectly.
// Keep import alive for tree-shaking transparency.
void LinearGradient;
