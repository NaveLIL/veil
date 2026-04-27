import React, { useMemo } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { Island } from "../ui/Island";
import { colors, radii, spacing } from "../../lib/theme";
import { DM_HOME_ID, useChatStore } from "../../stores/chat";

interface Props {
  onSelect: () => void;
}

export const ChannelsIsland: React.FC<Props> = ({ onSelect }) => {
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
    <View style={styles.wrap}>
      <Island padding={spacing.md} style={styles.island}>
        <Text style={styles.title}>{isDmHome ? "Direct messages" : server?.name ?? "Channels"}</Text>
        <Text style={styles.sub}>{isDmHome ? "people · groups" : "channels"}</Text>

        <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={styles.list}>
          {isDmHome
            ? dms.map((dm) => {
                const active = dm.id === selectedDmId;
                return (
                  <Pressable
                    key={dm.id}
                    onPress={() => {
                      selectDm(dm.id);
                      onSelect();
                    }}
                    style={({ pressed }) => [
                      styles.dmRow,
                      active && styles.rowActive,
                      pressed && { opacity: 0.7 },
                    ]}
                  >
                    <View
                      style={[
                        styles.avatar,
                        { backgroundColor: dm.color + "33", borderColor: dm.color + "55" },
                      ]}
                    >
                      <Text style={[styles.avatarText, { color: dm.color }]}>
                        {dm.isGroup ? "👥" : dm.name.charAt(0)}
                      </Text>
                    </View>
                    <View style={styles.dmMeta}>
                      <View style={styles.dmHead}>
                        <Text numberOfLines={1} style={styles.dmName}>
                          {dm.name}
                        </Text>
                        <Text style={styles.dmTime}>{dm.lastAt}</Text>
                      </View>
                      <View style={styles.dmHead}>
                        <Text numberOfLines={1} style={styles.dmLast}>
                          {dm.lastMessage}
                        </Text>
                        {dm.unread ? (
                          <View style={styles.badge}>
                            <Text style={styles.badgeText}>{dm.unread}</Text>
                          </View>
                        ) : null}
                      </View>
                    </View>
                  </Pressable>
                );
              })
            : channels.map((ch) => {
                const active = ch.id === selectedChannelId;
                const isVoice = ch.category === "VOICE";
                return (
                  <Pressable
                    key={ch.id}
                    onPress={() => {
                      selectChannel(ch.id);
                      onSelect();
                    }}
                    style={({ pressed }) => [
                      styles.chRow,
                      active && styles.rowActive,
                      pressed && { opacity: 0.7 },
                    ]}
                  >
                    <Text style={[styles.chPrefix, active && styles.chActive]}>
                      {isVoice ? "🔊" : "#"}
                    </Text>
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
  wrap: { flex: 1, paddingHorizontal: spacing.md, paddingBottom: spacing.md },
  island: { flex: 1 },
  title: { color: colors.textHi, fontSize: 18, fontWeight: "700" },
  sub: { color: colors.textLo, fontSize: 11, marginTop: 2, marginBottom: spacing.md, textTransform: "uppercase", letterSpacing: 1.5 },
  list: { paddingBottom: spacing.lg, gap: 4 },
  rowActive: { backgroundColor: "rgba(124,107,245,0.10)" },

  // channel row
  chRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    paddingHorizontal: spacing.sm,
    paddingVertical: 10,
    borderRadius: radii.md,
  },
  chPrefix: { color: colors.textLo, fontSize: 16, width: 22, textAlign: "center" },
  chActive: { color: colors.primary },
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
  avatar: {
    width: 44,
    height: 44,
    borderRadius: radii.pill,
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 1,
  },
  avatarText: { fontSize: 16, fontWeight: "700" },
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
