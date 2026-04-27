import React, { useMemo } from "react";
import { ScrollView, SectionList, StyleSheet, Text, View } from "react-native";
import { Island } from "../ui/Island";
import { colors, radii, spacing } from "../../lib/theme";
import { DM_HOME_ID, MEMBERS_BY_SERVER, Member, useChatStore } from "../../stores/chat";

const EMPTY_MEMBERS: Member[] = [];

const STATUS_COLOR: Record<Member["status"], string> = {
  online: "#34d399",
  idle: "#fbbf24",
  dnd: "#f04848",
  offline: "#7a7a90",
};

export const MembersIsland: React.FC = () => {
  const serverId = useChatStore((s) => s.selectedServerId);
  const members = useMemo(
    () => MEMBERS_BY_SERVER[serverId] ?? EMPTY_MEMBERS,
    [serverId],
  );

  const sections = useMemo(() => {
    const online = members.filter((m) => m.status !== "offline");
    const offline = members.filter((m) => m.status === "offline");
    return [
      { title: `Online — ${online.length}`, data: online },
      { title: `Offline — ${offline.length}`, data: offline },
    ];
  }, [members]);

  if (serverId === DM_HOME_ID) {
    return (
      <View style={styles.wrap}>
        <Island padding={spacing.md} style={styles.island}>
          <Text style={styles.title}>Details</Text>
          <Text style={styles.sub}>direct conversation</Text>
          <View style={styles.empty}>
            <Text style={styles.emptyTitle}>End-to-end encrypted</Text>
            <Text style={styles.emptyText}>
              Messages here are sealed with X3DH + Double Ratchet. Only you and the recipient can read them.
            </Text>
            <View style={styles.divider} />
            <Text style={styles.emptyHint}>Pinned · Media · Files coming soon</Text>
          </View>
        </Island>
      </View>
    );
  }

  return (
    <View style={styles.wrap}>
      <Island padding={spacing.md} style={styles.island}>
        <Text style={styles.title}>Members</Text>
        <Text style={styles.sub}>{members.length} total</Text>

        <SectionList
          sections={sections}
          keyExtractor={(m) => m.id}
          showsVerticalScrollIndicator={false}
          contentContainerStyle={{ paddingBottom: spacing.lg }}
          renderSectionHeader={({ section }) => (
            <Text style={styles.sectionHeader}>{section.title}</Text>
          )}
          renderItem={({ item }) => (
            <View style={styles.row}>
              <View style={[styles.avatar, { backgroundColor: item.color + "33", borderColor: item.color + "55" }]}>
                <Text style={[styles.avatarText, { color: item.color }]}>
                  {item.name.charAt(0).toUpperCase()}
                </Text>
                <View style={[styles.dot, { backgroundColor: STATUS_COLOR[item.status] }]} />
              </View>
              <View style={{ flex: 1 }}>
                <Text style={styles.name}>{item.name}</Text>
                {item.role && item.role !== "member" ? (
                  <Text style={styles.role}>{item.role}</Text>
                ) : (
                  <Text style={styles.statusLabel}>{item.status}</Text>
                )}
              </View>
            </View>
          )}
        />
      </Island>
    </View>
  );
};

const styles = StyleSheet.create({
  wrap: { flex: 1, paddingHorizontal: spacing.md, paddingBottom: spacing.md },
  island: { flex: 1 },
  title: { color: colors.textHi, fontSize: 18, fontWeight: "700" },
  sub: { color: colors.textLo, fontSize: 11, marginTop: 2, marginBottom: spacing.md, textTransform: "uppercase", letterSpacing: 1.5 },
  sectionHeader: {
    color: colors.textLo,
    fontSize: 10,
    letterSpacing: 1.5,
    fontWeight: "700",
    textTransform: "uppercase",
    marginTop: spacing.md,
    marginBottom: 6,
  },
  row: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
    paddingVertical: 8,
  },
  avatar: {
    width: 38,
    height: 38,
    borderRadius: radii.pill,
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 1,
  },
  avatarText: { fontSize: 14, fontWeight: "700" },
  dot: {
    position: "absolute",
    right: -2,
    bottom: -2,
    width: 12,
    height: 12,
    borderRadius: 6,
    borderWidth: 2,
    borderColor: colors.island,
  },
  name: { color: colors.textHi, fontSize: 14, fontWeight: "600" },
  role: { color: colors.primary, fontSize: 11, marginTop: 1, textTransform: "uppercase", letterSpacing: 1 },
  statusLabel: { color: colors.textLo, fontSize: 11, marginTop: 1 },

  empty: { flex: 1, paddingTop: spacing.xl },
  emptyTitle: { color: colors.textHi, fontSize: 15, fontWeight: "700" },
  emptyText: { color: colors.textMd, fontSize: 12, lineHeight: 18, marginTop: spacing.sm },
  divider: { height: StyleSheet.hairlineWidth, backgroundColor: colors.border, marginVertical: spacing.lg },
  emptyHint: { color: colors.textLo, fontSize: 11 },
});
