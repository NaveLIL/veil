import React, { useState, useEffect, useMemo } from "react";
import {
  KeyboardAvoidingView,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
  Image,
  Dimensions,
} from "react-native";
import type { NativeStackNavigationProp } from "@react-navigation/native-stack";
import { MessageCircle, Search } from "lucide-react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  useAnimatedProps,
  withTiming,
  withDelay,
  Easing,
  runOnJS,
} from "react-native-reanimated";
import Svg, { Rect, RadialGradient, Stop, Defs } from "react-native-svg";
import { LinearGradient } from "expo-linear-gradient";

import { UserAvatar } from "../components/identity/UserAvatar";
import { colors, radii, spacing } from "../lib/theme";
import { useChatStore } from "../stores/chat";
import VeilRuntime, { type NativeContactSearchResult } from "../native/runtime";
import type { AuthenticatedStackParamList } from "./ChatListScreen";
import { noiseBase64 } from "../components/ui/noiseBase64";
import { useReducedMotionPreference } from "../hooks/useReducedMotionPreference";

type Props = {
  navigation: NativeStackNavigationProp<AuthenticatedStackParamList>;
};

const AnimatedRadialGradient = Animated.createAnimatedComponent(RadialGradient);

const WINDOW = Dimensions.get("window");

export default function ContactSearchScreen({ navigation }: Props) {
  const insets = useSafeAreaInsets();
  const reducedMotion = useReducedMotionPreference();
  const [closing, setClosing] = useState(false);

  const [query, setQuery] = useState("");
  const [searching, setSearching] = useState(false);
  const [result, setResult] = useState<NativeContactSearchResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Animation values
  const scrimProgress = useSharedValue(0);
  const linearProgress = useSharedValue(0);
  const panelProgress = useSharedValue(0);

  useEffect(() => {
    if (reducedMotion) {
      scrimProgress.value = withTiming(1, { duration: 120 });
      linearProgress.value = withTiming(1, { duration: 120 });
      panelProgress.value = withTiming(1, { duration: 120 });
    } else {
      scrimProgress.value = withTiming(1, {
        duration: 260,
        easing: Easing.bezier(0.22, 1, 0.36, 1),
      });
      linearProgress.value = withTiming(1, {
        duration: 200,
        easing: Easing.out(Easing.ease),
      });
      panelProgress.value = withDelay(
        40,
        withTiming(1, { duration: 200, easing: Easing.out(Easing.ease) })
      );
    }
  }, [linearProgress, panelProgress, reducedMotion, scrimProgress]);

  const close = () => {
    if (closing) return;
    setClosing(true);
    const duration = reducedMotion ? 120 : 180;
    
    panelProgress.value = withTiming(0, { duration: reducedMotion ? 120 : 120 });
    linearProgress.value = withTiming(0, { duration });
    scrimProgress.value = withTiming(0, { duration }, (finished) => {
      if (finished) runOnJS(navigation.goBack)();
    });
  };

  const handleSearch = async () => {
    if (!query.trim() || !runtimeBinding) return;
    setSearching(true);
    setError(null);
    setResult(null);

    try {
      const username = query.trim();
      const req = await VeilRuntime.prepareContactSearch(username);
      
      const url = `${runtimeBinding.canonicalServerOrigin}${req.target}`;
      const response = await fetch(url, {
        method: req.method,
        headers: {
          "Accept": "application/json",
          "X-Veil-REST-Auth-Version": req.signature.version,
          "X-Veil-User": req.signature.userId,
          "X-Veil-Timestamp": req.signature.timestampMs,
          "X-Veil-Nonce": req.signature.nonceBase64url,
          "X-Veil-Signature": req.signature.signatureBase64url,
        },
      });

      if (!response.ok) {
        if (response.status === 404) {
          setError("User not found (exact match required).");
        } else {
          setError(`Network error: ${response.status}`);
        }
        return;
      }

      const buffer = await response.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      let binary = "";
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      const base64 = btoa(binary);

      const parsed = await VeilRuntime.parseContactSearchResponse(base64);
      setResult(parsed);
    } catch (err: any) {
      setError(err.message || "Failed to search. Check your connection.");
    } finally {
      setSearching(false);
    }
  };

  const handleStartDirect = async () => {
    if (!result || !runtimeBinding) return;
    setSearching(true);
    try {
      const req = await VeilRuntime.prepareCreateDirect(result.userId);
      const url = `${runtimeBinding.canonicalServerOrigin}${req.target}`;
      
      const bodyBytes = req.bodyBase64 ? Uint8Array.from(atob(req.bodyBase64), c => c.charCodeAt(0)) : undefined;
      
      const response = await fetch(url, {
        method: req.method,
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          "X-Veil-REST-Auth-Version": req.signature.version,
          "X-Veil-User": req.signature.userId,
          "X-Veil-Timestamp": req.signature.timestampMs,
          "X-Veil-Nonce": req.signature.nonceBase64url,
          "X-Veil-Signature": req.signature.signatureBase64url,
        },
        body: bodyBytes,
      });

      if (!response.ok) {
        throw new Error(`Failed to create Direct: ${response.status}`);
      }

      const responseBuffer = await response.arrayBuffer();
      const responseBytes = new Uint8Array(responseBuffer);
      let responseBinary = "";
      for (let i = 0; i < responseBytes.byteLength; i++) {
        responseBinary += String.fromCharCode(responseBytes[i]);
      }
      const parsed = await VeilRuntime.parseCreateDirectResponse(btoa(responseBinary));
      navigation.navigate("Direct", { conversationId: parsed.conversationId });
    } catch (err: any) {
      setError(err.message || "Failed to start direct message");
    } finally {
      setSearching(false);
    }
  };

  const runtimeBinding = useChatStore((s) => s.runtimeBinding);

  const hostname = useMemo(() => {
    if (!runtimeBinding?.canonicalServerOrigin) return "";
    try {
      return new URL(runtimeBinding.canonicalServerOrigin).hostname;
    } catch {
      return "";
    }
  }, [runtimeBinding]);

  const radialAnimatedProps = useAnimatedProps(() => {
    return {
      rx: `${scrimProgress.value * 140}%`,
      ry: `${scrimProgress.value * 45}%`,
    };
  });

  const linearStyle = useAnimatedStyle(() => ({
    opacity: linearProgress.value,
  }));

  const panelStyle = useAnimatedStyle(() => ({
    opacity: panelProgress.value,
    transform: [{
      translateY: (1 - panelProgress.value) * -10,
    }],
  }));

  const fallbackFadeStyle = useAnimatedStyle(() => ({
    opacity: scrimProgress.value,
  }));

  const headerHeight = insets.top + 60;
  // Use exact coordinates for the center of the radial gradient based on layout.
  // We approximate the center of the input: header height + 12px gap + 26px (half input height)
  const cyPixels = headerHeight + 12 + 26;
  const cyPercentage = (cyPixels / WINDOW.height) * 100;

  return (
    <View style={styles.root}>
      {/* z=10: Scrim Layer */}
      <View style={StyleSheet.absoluteFill} pointerEvents="auto">
        {/* Radial Gradient */}
        {reducedMotion ? (
          <Animated.View style={[StyleSheet.absoluteFill, fallbackFadeStyle, { backgroundColor: "rgba(0,0,0,0.6)" }]} />
        ) : (
          <Svg style={StyleSheet.absoluteFill}>
            <Defs>
              <AnimatedRadialGradient
                id="grad"
                cx="50%"
                cy={`${cyPercentage}%`}
                animatedProps={radialAnimatedProps}
              >
                <Stop offset="0%" stopColor="#000" stopOpacity="0" />
                <Stop offset="38%" stopColor="#000" stopOpacity="0" />
                <Stop offset="52%" stopColor="#000" stopOpacity="0.28" />
                <Stop offset="68%" stopColor="#000" stopOpacity="0.55" />
                <Stop offset="84%" stopColor="#000" stopOpacity="0.78" />
                <Stop offset="100%" stopColor="#000" stopOpacity="1" />
              </AnimatedRadialGradient>
            </Defs>
            <Rect width="100%" height="100%" fill="url(#grad)" />
          </Svg>
        )}

        {/* Linear Gradient (Top fade) */}
        <Animated.View style={[StyleSheet.absoluteFill, linearStyle]} pointerEvents="none">
          <LinearGradient
            colors={["rgba(0,0,0,1)", "rgba(0,0,0,0.85)", "rgba(0,0,0,0)"]}
            locations={[0, 0.06, 0.14]}
            style={StyleSheet.absoluteFill}
          />
        </Animated.View>

        {/* Dithering Noise */}
        <View pointerEvents="none" style={StyleSheet.absoluteFill}>
          <Image
            source={{ uri: noiseBase64 }}
            style={[StyleSheet.absoluteFill, { opacity: 0.025, resizeMode: "repeat" }]}
          />
        </View>

        {/* Dismiss trigger */}
        <Pressable style={StyleSheet.absoluteFill} onPress={close} />
      </View>

      {/* z=20: Panel Layer */}
      <KeyboardAvoidingView
        behavior={Platform.OS === "ios" ? "padding" : undefined}
        style={[styles.container, { paddingTop: headerHeight + 12 }]}
        pointerEvents="box-none"
      >
        <Animated.View style={[styles.panel, panelStyle]} pointerEvents="auto">
          <View style={styles.inputContainer}>
            <Search size={20} color={colors.textLo} style={styles.searchIcon} />
            <TextInput
              style={styles.input}
              placeholder="Exact username..."
              placeholderTextColor={colors.textLo}
              value={query}
              onChangeText={setQuery}
              autoCapitalize="none"
              autoCorrect={false}
              onSubmitEditing={handleSearch}
              returnKeyType="search"
              editable={!searching}
              autoFocus
            />
            {hostname ? (
              <Text style={styles.hostnameHint}>{hostname}</Text>
            ) : null}
            {query.length > 0 && !searching && (
               <Pressable onPress={() => setQuery("")} style={styles.clearBtn} hitSlop={12}>
                 <Text style={styles.clearBtnText}>×</Text>
               </Pressable>
            )}
          </View>

          {/* Results Area */}
          {(searching || error || result || query.length === 0) ? (
            <View style={styles.content}>
              {searching ? (
                <View style={styles.skeletonContainer}>
                  <View style={[styles.skeletonAvatar, styles.pulse]} />
                  <View style={styles.skeletonTextWrap}>
                    <View style={[styles.skeletonLine, styles.pulse, { width: "60%" }]} />
                    <View style={[styles.skeletonLine, styles.pulse, { width: "40%", marginTop: 6 }]} />
                  </View>
                </View>
              ) : error ? (
                <Text style={styles.errorText}>{error}</Text>
              ) : result ? (
                <View style={styles.resultCard}>
                  <UserAvatar
                    canonicalServerOrigin={runtimeBinding?.canonicalServerOrigin ?? ""}
                    userId={result.userId}
                    technicalUsername={result.username}
                    size={48}
                  />
                  <View style={styles.resultMeta}>
                    <Text style={styles.resultName}>@{result.username}</Text>
                    <Text style={styles.resultId}>{result.userId}</Text>
                  </View>
                  <Pressable
                    style={({ pressed }) => [styles.actionBtn, pressed && { opacity: 0.8 }]}
                    onPress={handleStartDirect}
                  >
                    <MessageCircle size={18} color={colors.textHi} />
                    <Text style={styles.actionLabel}>Message</Text>
                  </Pressable>
                </View>
              ) : query.length === 0 ? (
                <Text style={styles.emptyText}>Enter an exact username to search</Text>
              ) : null}
            </View>
          ) : null}
        </Animated.View>
      </KeyboardAvoidingView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
  },
  container: {
    flex: 1,
    paddingHorizontal: spacing.lg,
  },
  panel: {
    backgroundColor: "#2B2D31", // Opaque, one tone lighter than background
    borderRadius: 20, // matches system cards
    padding: spacing.lg,
  },
  inputContainer: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "transparent",
  },
  searchIcon: {
    marginRight: spacing.sm,
  },
  input: {
    flex: 1,
    height: 52, // as requested
    color: colors.textHi,
    fontSize: 16,
  },
  hostnameHint: {
    fontSize: 13,
    color: colors.textLo, // exactly same brightness as placeholder
    marginLeft: spacing.sm,
  },
  clearBtn: {
    marginLeft: spacing.sm,
    width: 24,
    height: 24,
    borderRadius: 12,
    backgroundColor: colors.surfaceLow,
    alignItems: "center",
    justifyContent: "center",
  },
  clearBtnText: {
    color: colors.textLo,
    fontSize: 14,
    fontWeight: "bold",
    marginTop: -2,
  },
  content: {
    marginTop: spacing.md,
    minHeight: 48,
    justifyContent: "center",
  },
  emptyText: {
    color: colors.textLo,
    fontSize: 14,
    textAlign: "center",
  },
  errorText: {
    color: colors.warning,
    fontSize: 14,
    textAlign: "center",
  },
  resultCard: {
    width: "100%",
    flexDirection: "row",
    alignItems: "center",
  },
  resultMeta: {
    flex: 1,
    marginLeft: spacing.md,
  },
  resultName: {
    color: colors.textHi,
    fontSize: 16,
    fontWeight: "600",
  },
  resultId: {
    color: colors.textLo,
    fontSize: 12,
    marginTop: 2,
  },
  actionBtn: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: colors.primary,
    paddingVertical: spacing.sm,
    paddingHorizontal: spacing.md,
    borderRadius: radii.pill,
    gap: spacing.sm,
  },
  actionLabel: {
    color: colors.textHi,
    fontSize: 14,
    fontWeight: "600",
  },
  skeletonContainer: {
    flexDirection: "row",
    alignItems: "center",
    width: "100%",
  },
  skeletonAvatar: {
    width: 48,
    height: 48,
    borderRadius: 24,
    backgroundColor: colors.surfaceLow,
  },
  skeletonTextWrap: {
    flex: 1,
    marginLeft: spacing.md,
  },
  skeletonLine: {
    height: 14,
    borderRadius: radii.sm,
    backgroundColor: colors.surfaceLow,
  },
  pulse: {
    opacity: 0.6,
  },
});
