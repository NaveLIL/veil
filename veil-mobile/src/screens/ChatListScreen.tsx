import React, { useMemo, useRef, useState } from "react";
import {
  StyleSheet,
  View,
  type NativeSyntheticEvent,
} from "react-native";
import PagerView, {
  type PagerViewOnPageSelectedEvent,
} from "react-native-pager-view";
import { GlowBlobs } from "../components/onboarding/GlowBlobs";
import { ChannelsIsland } from "../components/layout/ChannelsIsland";
import { ChatIsland } from "../components/layout/ChatIsland";
import { MembersIsland } from "../components/layout/MembersIsland";
import { ServerRailIsland } from "../components/layout/ServerRailIsland";
import { TopRail, type PageMeta } from "../components/layout/TopRail";
import { colors } from "../lib/theme";
import { DM_HOME_ID, useChatStore } from "../stores/chat";

const PAGES_BASE: PageMeta[] = [
  { key: "servers", label: "Servers", icon: "◇" },
  { key: "channels", label: "Channels", icon: "≡" },
  { key: "chat", label: "Chat", icon: "✦" },
  { key: "members", label: "Members", icon: "◉" },
];

export default function ChatListScreen() {
  const pagerRef = useRef<PagerView>(null);
  const [page, setPage] = useState(1);

  const selectedServerId = useChatStore((s) => s.selectedServerId);
  const selectedChannelId = useChatStore((s) => s.selectedChannelId);
  const selectedDmId = useChatStore((s) => s.selectedDmId);
  const channels = useChatStore((s) => s.channels);
  const dms = useChatStore((s) => s.dms);

  const isDmHome = selectedServerId === DM_HOME_ID;
  const chatTitle = useMemo(() => {
    if (isDmHome) {
      return dms.find((d) => d.id === selectedDmId)?.name ?? "Direct messages";
    }
    const ch = channels.find((c) => c.id === selectedChannelId);
    return ch ? `# ${ch.name}` : "Channel";
  }, [isDmHome, dms, selectedDmId, channels, selectedChannelId]);

  const pages = useMemo<PageMeta[]>(() => {
    if (!isDmHome) return PAGES_BASE;
    return [
      PAGES_BASE[0],
      { key: "channels", label: "Direct", icon: "@" },
      PAGES_BASE[2],
      { key: "members", label: "Details", icon: "ⓘ" },
    ];
  }, [isDmHome]);

  const subtitle = useMemo(() => {
    switch (page) {
      case 0:
        return "Your spaces";
      case 1:
        return isDmHome ? "Direct & groups" : "Channels";
      case 2:
        return "Conversation";
      case 3:
        return isDmHome ? "About this chat" : "Members";
      default:
        return undefined;
    }
  }, [page, isDmHome]);

  const headerTitle = page === 2 ? chatTitle : pages[page]?.label ?? "Veil";

  const goTo = (i: number) => {
    pagerRef.current?.setPage(i);
  };

  const onPageSelected = (
    e: NativeSyntheticEvent<PagerViewOnPageSelectedEvent["nativeEvent"]>,
  ) => {
    setPage(e.nativeEvent.position);
  };

  return (
    <View style={styles.root}>
      <View style={[StyleSheet.absoluteFill, styles.glowLayer]} pointerEvents="none">
        <GlowBlobs />
      </View>

      <TopRail
        pages={pages}
        activeIndex={page}
        onPress={goTo}
        title={headerTitle}
        subtitle={subtitle}
      />

      <PagerView
        ref={pagerRef}
        style={styles.pager}
        initialPage={1}
        offscreenPageLimit={3}
        onPageSelected={onPageSelected}
      >
        <View key="servers" style={styles.page}>
          <ServerRailIsland onSelect={() => goTo(1)} />
        </View>
        <View key="channels" style={styles.page}>
          <ChannelsIsland onSelect={() => goTo(2)} />
        </View>
        <View key="chat" style={styles.page}>
          <ChatIsland />
        </View>
        <View key="members" style={styles.page}>
          <MembersIsland />
        </View>
      </PagerView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  glowLayer: { opacity: 0.4 },
  pager: { flex: 1 },
  page: { flex: 1 },
});
