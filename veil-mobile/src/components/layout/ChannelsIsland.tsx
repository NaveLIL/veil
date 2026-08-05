import React, { useMemo } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { ChevronRight, Hash, Search, UsersRound, Volume2 } from "lucide-react-native";
import { useIsFocused } from "@react-navigation/native";
import { Island } from "../ui/Island";
import { colors, radii, spacing } from "../../lib/theme";
import { DM_HOME_ID, useChatStore } from "../../stores/chat";
import { UserAvatar } from "../identity/UserAvatar";

interface Props {
  onSelect: (targetId: string) => void;
  onSearchContacts?: () => void;
  bottomInset?: number;
  leftInset?: number;
  rightInset?: number;
}

export const ChannelsIsland: React.FC<Props> = ({
  onSelect,
  onSearchContacts,
  bottomInset = 0,
  leftInset = 0,
  rightInset = 0,
}) => {
  const isFocused = useIsFocused();
  const serverId = useChatStore((s) => s.selectedServerId);
  const servers = useChatStore((s) => s.servers);
  const allChannels = useChatStore((s) => s.channels);
  const dms = useChatStore((s) => s.dms);
  const selectedChannelId = useChatStore((s) => s.selectedChannelId);
  const selectedDmId = useChatStore((s) => s.selectedDmId);
  const selectChannel = useChatStore((s) => s.selectChannel);
  const selectDm = useChatStore((s) => s.selectDm);

  const isDmHome = serverId === DM_HOME_ID;
  const server = useMemo(() => servers.find((s) => s.id === serverId), [servers, serverId]);
  const channels = useMemo(
    () => allChannels.filter((c) => c.serverId === serverId),
    [allChannels, serverId],
  );

  return (
    <View
      testID="channels-island-wrap"
      style={[
        styles.wrap,
        {
          paddingBottom: Math.max(spacing.md, bottomInset),
          paddingLeft: Math.max(spacing.md, leftInset),
          paddingRight: Math.max(spacing.md, rightInset),
        },
      ]}
    >
      <Island variant="solid" glow={false} padding={spacing.md} style={styles.island}>
        <Text style={styles.title}>{isDmHome ? "Direct messages" : server?.name ?? "Channels"}</Text>
        <Text style={styles.sub}>{isDmHome ? "private conversations" : "rooms"}</Text>

        <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={styles.list}>
          {isDmHome && dms.length === 0 ? (
            <View testID="direct-directory-empty" style={styles.emptyDirectory}>
              <Text style={styles.emptyTitle}>No Direct conversations yet</Text>
              <Text style={styles.emptyText}>
                Conversations appear here only after the authenticated native directory is ready.
              </Text>
            </View>
          ) : null}
          {isDmHome && onSearchContacts && isFocused ? (
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Find contacts"
              onPress={onSearchContacts}
              style={({ pressed }) => [
                styles.dmRow,
                {
                  backgroundColor: colors.surfaceLow,
                  borderRadius: radii.md,
                  paddingHorizontal: spacing.md,
                  paddingVertical: spacing.md,
                  marginTop: spacing.sm,
                  marginBottom: spacing.xs,
                },
                pressed && { opacity: 0.7 }
              ]}
            >
              <Search size={18} strokeWidth={2.2} color={colors.primary} />
              <View style={[styles.dmMeta, { marginLeft: spacing.md }]}>
                <Text numberOfLines={1} style={[styles.dmName, { color: colors.primary }]}>
                  Find contacts
                </Text>
              </View>
              <ChevronRight size={18} strokeWidth={2.2} color={colors.primary} style={{ opacity: 0.5 }} />
            </Pressable>
          ) : null}
          {isDmHome
            ? dms.map((dm) => {
                const active = dm.id === selectedDmId;
                return (
                  <Pressable
                    key={dm.id}
                    accessibilityRole="button"
                    accessibilityLabel={`${dm.name}. Direct conversation`}
                    accessibilityState={{ selected: active }}
                    onPress={() => {
                      selectDm(dm.id);
                      onSelect(dm.id);
                    }}
                    style={({ pressed }) => [
                      styles.dmRow,
                      active && styles.rowActive,
                      pressed && { opacity: 0.7 },
                    ]}
                  >
                    {dm.isGroup || !dm.avatarIdentity ? (
                      <View
                        accessibilityLabel="Group conversation"
                        accessibilityRole="image"
                        style={[styles.groupAvatar, { borderColor: `${dm.color}55` }]}
                      >
                        <UsersRound size={21} strokeWidth={1.9} color={dm.color} />
                      </View>
                    ) : (
                      <UserAvatar
                        canonicalServerOrigin={dm.avatarIdentity.canonicalServerOrigin}
                        userId={dm.avatarIdentity.userId}
                        technicalUsername={dm.avatarIdentity.username}
                        size={44}
                      />
                    )}
                    <View style={styles.dmMeta}>
                      <View style={styles.dmHead}>
                        <Text numberOfLines={1} style={styles.dmName}>
                          {dm.name}
                        </Text>
                        {dm.lastAt ? <Text style={styles.dmTime}>{dm.lastAt}</Text> : null}
                      </View>
                      <View style={styles.dmHead}>
                        <Text numberOfLines={1} style={styles.dmLast}>
                          {dm.lastMessage ?? "Tap to open encrypted history"}
                        </Text>
                      </View>
                    </View>
                  </Pressable>
                );
              })
            : channels.map((ch) => {
                const active = ch.id === selectedChannelId;
                const isVoice = ch.category === "VOICE";
                const PrefixIcon = isVoice ? Volume2 : Hash;
                return (
                  <Pressable
                    key={ch.id}
                    onPress={() => {
                      selectChannel(ch.id);
                      onSelect(ch.id);
                    }}
                    style={({ pressed }) => [
                      styles.chRow,
                      active && styles.rowActive,
                      pressed && { opacity: 0.7 },
                    ]}
                  >
                    <View style={styles.chPrefix}>
                      <PrefixIcon
                        size={16}
                        strokeWidth={2}
                        color={active ? colors.primary : colors.textLo}
                      />
                    </View>
                    <Text
                      numberOfLines={1}
                      style={[
                        styles.chName,
                        active && styles.chNameActive,
                      ]}
                    >
                      {ch.name}
                    </Text>
                    {ch.unread ? (
                      <View style={styles.badge}>
                        <Text style={styles.badgeText}>{ch.unread}</Text>
                      </View>
                    ) : null}
                  </Pressable>
                );
              })}
        </ScrollView>
      </Island>
    </View>
  );
};

const styles = StyleSheet.create({
  wrap: { flex: 1 },
  island: { flex: 1 },
  title: { color: colors.textHi, fontSize: 18, fontWeight: "700" },
  sub: { color: colors.textLo, fontSize: 11, marginTop: 2, marginBottom: spacing.md, textTransform: "uppercase", letterSpacing: 1.5 },
  list: { paddingBottom: spacing.lg, gap: 4 },
  emptyDirectory: {
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.xl,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    borderRadius: radii.lg,
    backgroundColor: "rgba(255,255,255,0.025)",
  },
  emptyTitle: { color: colors.textMd, fontSize: 14, fontWeight: "700" },
  emptyText: { color: colors.textLo, fontSize: 12, lineHeight: 18, marginTop: 5 },
  rowActive: { backgroundColor: "rgba(124,107,245,0.10)" },

  // channel row
  chRow: {
    minHeight: 48,
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    paddingHorizontal: spacing.sm,
    paddingVertical: 10,
    borderRadius: radii.md,
  },
  chPrefix: { width: 22, alignItems: "center", justifyContent: "center" },
  chName: { color: colors.textMd, fontSize: 15, flex: 1 },
  chNameActive: { color: colors.textHi, fontWeight: "600" },

  // dm row
  dmRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.sm,
    borderRadius: radii.lg,
  },
  groupAvatar: {
    width: 44,
    height: 44,
    borderRadius: radii.lg,
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 1,
    backgroundColor: "rgba(124,107,245,0.10)",
  },
  dmMeta: { flex: 1, minWidth: 0 },
  dmHead: { flexDirection: "row", alignItems: "center", gap: spacing.sm },
  dmName: { color: colors.textHi, fontSize: 14, fontWeight: "600", flex: 1 },
  dmTime: { color: colors.textLo, fontSize: 11 },
  dmLast: { color: colors.textMd, fontSize: 12, flex: 1, marginTop: 2 },

  badge: {
    minWidth: 20,
    height: 20,
    paddingHorizontal: 6,
    borderRadius: radii.pill,
    backgroundColor: colors.primary,
    alignItems: "center",
    justifyContent: "center",
  },
  badgeText: { color: "#fff", fontSize: 10, fontWeight: "700" },
});
