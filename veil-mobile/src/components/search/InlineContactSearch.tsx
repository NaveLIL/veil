import React, { useState, useEffect, useMemo } from "react";
import {
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
  Image,
} from "react-native";
import { MessageCircle, Search, X } from "lucide-react-native";
import Svg, { Rect, RadialGradient, Stop, Defs } from "react-native-svg";
import { useNavigation } from "@react-navigation/native";

import { UserAvatar } from "../identity/UserAvatar";
import { colors, radii, spacing } from "../../lib/theme";
import { useChatStore } from "../../stores/chat";
import VeilRuntime, { type NativeContactSearchResult } from "../../native/runtime";
import { noiseBase64 } from "../ui/noiseBase64";

interface Props {
  onExit: () => void;
}

export function InlineContactSearch({ onExit }: Props) {
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [searching, setSearching] = useState(false);
  const [result, setResult] = useState<NativeContactSearchResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const runtimeBinding = useChatStore((s) => s.runtimeBinding);
  const navigation = useNavigation<any>();

  // Debounce logic
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(query.trim()), 300);
    return () => clearTimeout(timer);
  }, [query]);

  // Search logic
  useEffect(() => {
    if (!debouncedQuery) {
      setResult(null);
      setError(null);
      setSearching(false);
      return;
    }
    
    let active = true;

    const performSearch = async () => {
      if (!runtimeBinding) return;
      setSearching(true);
      setError(null);
      setResult(null);

      try {
        const req = await VeilRuntime.prepareContactSearch(debouncedQuery);
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

        if (!active) return;

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
        if (active) setResult(parsed);
      } catch (err: any) {
        if (active) setError(err.message || "Failed to search. Check your connection.");
      } finally {
        if (active) setSearching(false);
      }
    };

    performSearch();
    return () => { active = false; };
  }, [debouncedQuery, runtimeBinding]);

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

      // Step 7: Read binary response as base64
      const responseBuffer = await response.arrayBuffer();
      const responseBase64 = btoa(String.fromCharCode(...new Uint8Array(responseBuffer)));
      
      // Step 8: Parse response in Rust
      const parsed = await VeilRuntime.parseCreateDirectResponse(responseBase64);

      onExit();
      // Navigate to the direct conversation view
      // Cast navigation to any to avoid type check error in this local component
      (navigation as any).navigate("Direct", { conversationId: parsed.conversationId });
    } catch (err: any) {
      setError(err.message || "Failed to start direct message");
    } finally {
      setSearching(false);
    }
  };

  const hostname = useMemo(() => {
    if (!runtimeBinding?.canonicalServerOrigin) return "";
    try {
      return new URL(runtimeBinding.canonicalServerOrigin).hostname;
    } catch {
      return "";
    }
  }, [runtimeBinding]);

  return (
    <View style={styles.root}>
      {/* Optional Under-Panel Glow Z=1 */}
      <View style={[StyleSheet.absoluteFill, { pointerEvents: "none", zIndex: 1, marginTop: -40 }]}>
        <Svg height={240} width="100%">
          <Defs>
            <RadialGradient id="glow" cx="50%" cy="28" rx="60%" ry="100%">
              <Stop offset="0%" stopColor="#ffffff" stopOpacity="0.03" />
              <Stop offset="100%" stopColor="#ffffff" stopOpacity="0" />
            </RadialGradient>
          </Defs>
          <Rect x="0" y="0" width="100%" height={240} fill="url(#glow)" />
        </Svg>
        <Image
          source={{ uri: noiseBase64 }}
          style={[StyleSheet.absoluteFill, { opacity: 0.025, resizeMode: "repeat", height: 240 }]}
        />
      </View>

      {/* Main Content Z=10 */}
      <View style={{ zIndex: 10 }}>
        {/* Search Panel */}
        <View style={styles.panel}>
          <Search size={20} color={colors.textLo} style={styles.searchIcon} />
          <TextInput
            style={styles.input}
            placeholder="Exact username..."
            placeholderTextColor={colors.textLo}
            value={query}
            onChangeText={setQuery}
            autoCapitalize="none"
            autoCorrect={false}
            returnKeyType="search"
            autoFocus
          />
          {hostname ? (
            <Text style={styles.hostnameHint}>{hostname}</Text>
          ) : null}
          <Pressable 
            onPress={() => {
              if (query.length > 0) {
                setQuery("");
              } else {
                onExit();
              }
            }} 
            style={styles.actionBtnHitbox}
            hitSlop={12}
          >
            <X size={18} color={colors.textLo} />
          </Pressable>
        </View>

        {/* Results Zone */}
        <View style={styles.resultsZone}>
          {searching ? (
            <View style={styles.skeletonList}>
              {[1, 2, 3].map((i) => (
                <View key={i} style={styles.skeletonIsland}>
                  <View style={[styles.skeletonAvatar, styles.pulse]} />
                  <View style={styles.skeletonTextWrap}>
                    <View style={[styles.skeletonLine, styles.pulse, { width: "60%" }]} />
                    <View style={[styles.skeletonLine, styles.pulse, { width: "40%", marginTop: 6 }]} />
                  </View>
                </View>
              ))}
            </View>
          ) : error ? (
            <View style={styles.centerMessage}>
              <Text style={styles.errorText}>{error}</Text>
              <Pressable onPress={() => setDebouncedQuery(query.trim() + " ")} style={styles.retryBtn}>
                <Text style={styles.retryText}>Retry</Text>
              </Pressable>
            </View>
          ) : result ? (
            <View style={styles.resultIsland}>
              <UserAvatar
                canonicalServerOrigin={runtimeBinding?.canonicalServerOrigin ?? ""}
                userId={result.userId}
                technicalUsername={result.username}
                size={40}
              />
              <View style={styles.resultMeta}>
                <Text style={styles.resultName}>@{result.username}</Text>
                <Text style={styles.resultId}>{result.userId}</Text>
              </View>
              <Pressable
                style={({ pressed }) => [styles.messageBtn, pressed && { opacity: 0.8 }]}
                onPress={handleStartDirect}
              >
                <MessageCircle size={18} color={colors.textHi} />
              </Pressable>
            </View>
          ) : (
            <Text style={styles.emptyText}>Enter an exact username to search</Text>
          )}
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: {
    // We let the parent dictate positioning; this just holds the search panel + results
  },
  panel: {
    height: 56, // exactly 56px
    backgroundColor: colors.surfaceSolid, // same as island
    borderRadius: radii.xl, // matches island/header radius
    paddingHorizontal: spacing.lg, // 16px
    flexDirection: "row",
    alignItems: "center",
  },
  searchIcon: {
    marginRight: spacing.sm,
  },
  input: {
    flex: 1,
    height: "100%",
    color: colors.textHi,
    fontSize: 16,
    padding: 0,
    backgroundColor: "transparent",
  },
  hostnameHint: {
    fontSize: 13,
    color: colors.textLo, // same brightness as placeholder
    marginLeft: spacing.sm,
  },
  actionBtnHitbox: {
    marginLeft: spacing.sm,
    width: 24,
    height: 24,
    alignItems: "center",
    justifyContent: "center",
  },
  resultsZone: {
    marginTop: 12,
  },
  emptyText: {
    color: colors.textLo,
    fontSize: 14,
    textAlign: "center",
    marginTop: spacing.xl,
  },
  centerMessage: {
    alignItems: "center",
    marginTop: spacing.xl,
  },
  errorText: {
    color: colors.textHi,
    fontSize: 14,
    textAlign: "center",
  },
  retryBtn: {
    marginTop: spacing.md,
    backgroundColor: colors.surfaceLow,
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.sm,
    borderRadius: radii.pill,
  },
  retryText: {
    color: colors.textHi,
    fontSize: 14,
    fontWeight: "500",
  },
  skeletonList: {
    gap: 8,
  },
  skeletonIsland: {
    height: 64,
    backgroundColor: colors.surfaceSolid,
    borderRadius: radii.xl,
    paddingHorizontal: spacing.lg,
    flexDirection: "row",
    alignItems: "center",
  },
  skeletonAvatar: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: colors.surfaceLow,
  },
  skeletonTextWrap: {
    flex: 1,
    marginLeft: spacing.md,
  },
  skeletonLine: {
    height: 12,
    borderRadius: radii.sm,
    backgroundColor: colors.surfaceLow,
  },
  pulse: {
    opacity: 0.6,
  },
  resultIsland: {
    height: 64,
    backgroundColor: colors.surfaceSolid,
    borderRadius: radii.xl,
    paddingHorizontal: spacing.lg,
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
  messageBtn: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: colors.primary,
    alignItems: "center",
    justifyContent: "center",
  },
});
