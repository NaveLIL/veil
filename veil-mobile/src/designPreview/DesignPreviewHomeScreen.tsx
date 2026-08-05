import React, { useEffect, useRef, useState } from "react";
import { Animated, BackHandler, Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";
import {
  ChevronRight,
  Circle,
  Settings2,
  type LucideIcon,
} from "lucide-react-native";

import { ChannelsIsland } from "../components/layout/ChannelsIsland";
import { MobileHeader } from "../components/navigation/MobileHeader";
import { RootDock, type RootDestination } from "../components/navigation/RootDock";
import { Island } from "../components/ui/Island";
import { InlineContactSearch } from "../components/search/InlineContactSearch";
import { useReducedMotionPreference } from "../hooks/useReducedMotionPreference";
import { colors, radii, spacing } from "../lib/theme";
import { useChatStore } from "../stores/chat";
import type { DesignPreviewStackParamList } from "./navigation";
import Reanimated, {
  useSharedValue,
  useAnimatedStyle,
  withTiming,
  withDelay,
  Easing,
  interpolateColor,
} from "react-native-reanimated";
import { useSafeAreaInsets } from "react-native-safe-area-context";

type Props = NativeStackScreenProps<DesignPreviewStackParamList, "Home">;

export default function DesignPreviewHomeScreen({ navigation }: Props) {
  const [destination, setDestination] = useState<RootDestination>("home");
  const [activeTab, setActiveTab] = useState<RootDestination>("home");
  const [isSearching, setIsSearching] = useState(false);
  const insets = useSafeAreaInsets();
  const reducedMotion = useReducedMotionPreference();
  const contentProgress = useRef(new Animated.Value(1)).current; // For Tab switching

  // Reanimated values for Search Transition
  const searchProgress = useSharedValue(0);
  const headerOpacity = useSharedValue(1);
  const headerY = useSharedValue(0);
  const panelOpacity = useSharedValue(0);

  const runtimeBinding = useChatStore((state) => state.runtimeBinding);
  const shortId = runtimeBinding?.userId ? runtimeBinding.userId.slice(0, 8) : "---";

  const header = destination === "home"
    ? { title: "Home", subtitle: `Your private center • ${shortId}` }
    : destination === "spaces"
      ? { title: "Spaces", subtitle: "Circles and Rooms" }
      : { title: "Updates", subtitle: "Mentions, replies and invitations" };

  useEffect(() => {
    if (reducedMotion) {
      contentProgress.setValue(1);
      return;
    }
    const animation = Animated.timing(contentProgress, {
      toValue: 1,
      duration: 170,
      useNativeDriver: true,
    });
    animation.start();
    return () => animation.stop();
  }, [contentProgress, destination, reducedMotion]);

  useEffect(() => {
    if (reducedMotion) {
      searchProgress.value = withTiming(isSearching ? 1 : 0, { duration: 120 });
      headerOpacity.value = withTiming(isSearching ? 0 : 1, { duration: 120 });
      panelOpacity.value = withTiming(isSearching ? 1 : 0, { duration: 120 });
      headerY.value = 0;
    } else {
      if (isSearching) {
        headerOpacity.value = withTiming(0, { duration: 160, easing: Easing.out(Easing.ease) });
        headerY.value = withTiming(-8, { duration: 160, easing: Easing.out(Easing.ease) });
        searchProgress.value = withTiming(1, { duration: 220, easing: Easing.linear });
        panelOpacity.value = withDelay(100, withTiming(1, { duration: 200, easing: Easing.out(Easing.ease) }));
      } else {
        panelOpacity.value = withTiming(0, { duration: 120, easing: Easing.out(Easing.ease) });
        searchProgress.value = withTiming(0, { duration: 180, easing: Easing.linear });
        headerOpacity.value = withDelay(60, withTiming(1, { duration: 120, easing: Easing.out(Easing.ease) }));
        headerY.value = withDelay(60, withTiming(0, { duration: 120, easing: Easing.out(Easing.ease) }));
      }
    }
  }, [headerOpacity, headerY, isSearching, panelOpacity, reducedMotion, searchProgress]);

  useEffect(() => {
    const backAction = () => {
      if (isSearching) {
        setIsSearching(false);
        return true;
      }
      return false;
    };
    const backHandler = BackHandler.addEventListener("hardwareBackPress", backAction);
    return () => backHandler.remove();
  }, [isSearching]);

  const selectDestination = (newDest: RootDestination) => {
    if (newDest === activeTab) return;
    if (isSearching) setIsSearching(false);
    setActiveTab(newDest);
    if (reducedMotion) {
      contentProgress.setValue(1);
      setDestination(newDest);
      return;
    }
    Animated.timing(contentProgress, {
      toValue: 0,
      duration: 100,
      useNativeDriver: true,
    }).start(() => {
      setDestination(newDest);
      Animated.timing(contentProgress, {
        toValue: 1,
        duration: 150,
        useNativeDriver: true,
      }).start();
    });
  };

  const bgStyle = useAnimatedStyle(() => ({
    backgroundColor: interpolateColor(
      searchProgress.value,
      [0, 1],
      [colors.background, "#000000"]
    ),
  }));

  const mainContentStyle = useAnimatedStyle(() => ({
    opacity: headerOpacity.value,
    transform: [{ translateY: headerY.value }],
  }));

  const searchOverlayStyle = useAnimatedStyle(() => ({
    opacity: panelOpacity.value,
  }));

  return (
    <Reanimated.View testID="home-screen" style={[styles.root, bgStyle]}>
      {/* Main Content */}
      <Reanimated.View style={[{ flex: 1 }, mainContentStyle]} pointerEvents={isSearching ? "none" : "auto"}>
        <MobileHeader
          showBrand
          title={header.title}
          subtitle={header.subtitle}
          action={{
            label: "Settings",
            accessibilityLabel: "Open Settings",
            icon: Settings2,
            onPress: () => navigation.navigate("Settings"),
          }}
        />
        <Animated.View
          style={[
            styles.body,
            reducedMotion ? null : {
              opacity: contentProgress,
              transform: [{
                translateY: contentProgress.interpolate({
                  inputRange: [0, 1],
                  outputRange: [5, 0],
                }),
              }],
            },
          ]}
        >
          {destination === "home" ? (
            <ChannelsIsland
              onSelect={(conversationId) => navigation.navigate("Direct", { conversationId })}
              onSearchContacts={() => setIsSearching(true)}
            />
          ) : destination === "spaces" ? (
            <SpacesPreview
              onOpenCircle={() => navigation.navigate("DesignCircle")}
              onOpenSpace={() => navigation.navigate("DesignSpace")}
            />
          ) : (
            <UpdatesPreview
              onOpenCircle={() => navigation.navigate("DesignCircle")}
              onOpenRoom={() => navigation.navigate("DesignRoom", { roomId: "mobile-design" })}
            />
          )}
        </Animated.View>
      </Reanimated.View>

      {/* Inline Search Overlay */}
      <Reanimated.View 
        style={[StyleSheet.absoluteFill, searchOverlayStyle]} 
        pointerEvents={isSearching ? "box-none" : "none"}
      >
        <View style={{ paddingTop: insets.top + spacing.md, paddingHorizontal: spacing.lg }}>
          <InlineContactSearch onExit={() => setIsSearching(false)} />
        </View>
      </Reanimated.View>

      <Reanimated.View 
        style={mainContentStyle} 
        pointerEvents={isSearching ? "none" : "auto"}
      >
        <RootDock active={activeTab} onSelect={selectDestination} />
      </Reanimated.View>
    </Reanimated.View>
  );
}

function SpacesPreview({
  onOpenCircle,
  onOpenSpace,
}: {
  onOpenCircle: () => void;
  onOpenSpace: () => void;
}) {
  return (
    <ScrollView
      testID="spaces-preview"
      contentContainerStyle={styles.previewContent}
      showsVerticalScrollIndicator={false}
    >
      <PreviewBanner text="Local-only fixtures for approving Circle, Space, text Room and Voice Room navigation" />
      <Text style={styles.collectionLabel}>Circles</Text>
      <Island variant="solid" glow={false} padding={0}>
        <PreviewContextRow
          icon={Circle}
          title="Design Circle"
          subtitle="Circle · 4 members · one conversation"
          mentionCount={1}
          onPress={onOpenCircle}
        />
      </Island>
      <Text style={styles.collectionLabel}>Spaces</Text>
      <Island variant="solid" glow={false} padding={0}>
        <PreviewContextRow
          mark="DS"
          title="Design Space"
          subtitle="Space · 5 Rooms · 4 members"
          mentionCount={3}
          onPress={onOpenSpace}
        />
      </Island>
      <Text style={styles.previewFootnote}>
        Design preview is visibly isolated from the authenticated Node projection. Create, join, send and role actions stay unavailable.
      </Text>
    </ScrollView>
  );
}

function UpdatesPreview({
  onOpenCircle,
  onOpenRoom,
}: {
  onOpenCircle: () => void;
  onOpenRoom: () => void;
}) {
  return (
    <ScrollView
      testID="updates-preview"
      contentContainerStyle={styles.previewContent}
      showsVerticalScrollIndicator={false}
    >
      <PreviewBanner text="Preview examples only · no real notification was received" />
      <Island variant="solid" glow={false} padding={0}>
        <ActivityRow
          badge="@2"
          title="Mention in #mobile-design"
          path="Design Space › Product › #mobile-design"
          onPress={onOpenRoom}
        />
        <ActivityRow
          badge="@1"
          title="Mention in Design Circle"
          path="Design Circle › conversation"
          onPress={onOpenCircle}
          divided
        />
      </Island>
      <Text style={styles.previewFootnote}>
        Live updates will return you to the exact Direct, Circle or Room and re-check access before opening it.
      </Text>
    </ScrollView>
  );
}

function PreviewContextRow({
  mark,
  icon,
  title,
  subtitle,
  mentionCount,
  onPress,
}: {
  mark?: string;
  icon?: LucideIcon;
  title: string;
  subtitle: string;
  mentionCount: number;
  onPress: () => void;
}) {
  const Icon = icon;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`${title}. Design preview. ${mentionCount} mentions`}
      onPress={onPress}
      style={({ pressed }) => [styles.contextRow, pressed && styles.pressed]}
    >
      <View style={styles.previewMark}>
        {Icon ? (
          <Icon size={20} strokeWidth={2} color={colors.primaryHi} />
        ) : (
          <Text style={styles.previewMarkText}>{mark ?? ""}</Text>
        )}
      </View>
      <View style={styles.previewMeta}>
        <Text style={styles.previewTitle}>{title}</Text>
        <Text style={styles.contextSubtitle}>{subtitle}</Text>
      </View>
      <View style={styles.mentionBadge}><Text style={styles.mentionText}>@{mentionCount}</Text></View>
      <ChevronRight size={19} strokeWidth={1.8} color={colors.textLo} />
    </Pressable>
  );
}

function ActivityRow({
  badge,
  title,
  path,
  onPress,
  divided = false,
}: {
  badge: string;
  title: string;
  path: string;
  onPress: () => void;
  divided?: boolean;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`${title}. ${path}. Design preview`}
      onPress={onPress}
      style={({ pressed }) => [styles.activityRow, divided && styles.divider, pressed && styles.pressed]}
    >
      <View style={styles.activityBadge}><Text style={styles.activityBadgeText}>{badge}</Text></View>
      <View style={styles.previewMeta}>
        <Text style={styles.activityTitle}>{title}</Text>
        <Text numberOfLines={2} style={styles.activityPath}>{path}</Text>
      </View>
      <ChevronRight size={19} strokeWidth={1.8} color={colors.textLo} />
    </Pressable>
  );
}

function PreviewBanner({ text }: { text: string }) {
  return (
    <View style={styles.previewBanner}>
      <Text style={styles.previewBannerLabel}>DESIGN PREVIEW</Text>
      <Text style={styles.previewBannerText}>{text}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  body: { flex: 1 },
  previewContent: {
    paddingHorizontal: spacing.md,
    paddingBottom: spacing.md,
    gap: spacing.sm,
  },
  previewBanner: {
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    borderRadius: radii.md,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.warningBorder,
    backgroundColor: colors.warningBg,
  },
  previewBannerLabel: { color: colors.warning, fontSize: 9, fontWeight: "900", letterSpacing: 1.2 },
  previewBannerText: { color: colors.textMd, fontSize: 10, lineHeight: 15, marginTop: 2 },
  collectionLabel: { color: colors.textLo, fontSize: 9, fontWeight: "900", letterSpacing: 1.3, textTransform: "uppercase", marginLeft: spacing.sm, marginTop: spacing.xs },
  contextRow: { minHeight: 64, flexDirection: "row", alignItems: "center", gap: spacing.md, padding: spacing.md },
  previewMark: {
    width: 44,
    height: 44,
    alignItems: "center",
    justifyContent: "center",
    borderRadius: radii.lg,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: "rgba(124,107,245,0.32)",
    backgroundColor: "rgba(124,107,245,0.10)",
  },
  previewMarkText: { color: colors.primaryHi, fontSize: 13, fontWeight: "900" },
  previewMeta: { flex: 1, minWidth: 0 },
  previewTitle: { color: colors.textHi, fontSize: 14, fontWeight: "800" },
  contextSubtitle: { color: colors.textLo, fontSize: 10, marginTop: 2 },
  previewFootnote: {
    color: colors.textLo,
    fontSize: 11,
    lineHeight: 17,
    textAlign: "center",
    paddingHorizontal: spacing.lg,
  },
  mentionBadge: {
    minWidth: 28,
    height: 20,
    alignItems: "center",
    justifyContent: "center",
    borderRadius: radii.pill,
    backgroundColor: colors.primary,
  },
  mentionText: { color: "white", fontSize: 9, fontWeight: "900" },
  activityRow: { minHeight: 68, flexDirection: "row", alignItems: "center", gap: spacing.md, padding: spacing.md },
  activityBadge: { minWidth: 34, height: 28, alignItems: "center", justifyContent: "center", paddingHorizontal: 6, borderRadius: radii.pill, backgroundColor: colors.primary },
  activityBadgeText: { color: "white", fontSize: 10, fontWeight: "900" },
  activityTitle: { color: colors.textHi, fontSize: 13, fontWeight: "800" },
  activityPath: { color: colors.textLo, fontSize: 10, lineHeight: 14, marginTop: 3 },
  divider: { borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: colors.borderSoft },
  pressed: { opacity: 0.66, backgroundColor: colors.surfaceLow },
});
