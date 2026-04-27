import React from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { Island } from "../ui/Island";
import { colors, radii, spacing } from "../../lib/theme";
import { DM_HOME_ID, useChatStore } from "../../stores/chat";

interface Props {
  onSelect: () => void;
}

export const ServerRailIsland: React.FC<Props> = ({ onSelect }) => {
  const servers = useChatStore((s) => s.servers);
  const selectedServerId = useChatStore((s) => s.selectedServerId);
  const selectServer = useChatStore((s) => s.selectServer);

  return (
    <View style={styles.wrap}>
      <Island padding={spacing.md} style={styles.island}>
        <Text style={styles.heading}>Servers</Text>
        <ScrollView
          showsVerticalScrollIndicator={false}
          contentContainerStyle={styles.list}
        >
          {servers.map((server) => {
            const active = server.id === selectedServerId;
            const isDm = server.id === DM_HOME_ID;
            return (
              <Pressable
                key={server.id}
                onPress={() => {
                  selectServer(server.id);
                  onSelect();
                }}
                style={({ pressed }) => [
                  styles.row,
                  active && styles.rowActive,
                  pressed && { opacity: 0.7 },
                ]}
              >
                <View style={[styles.bar, active && styles.barActive]} />
                <View
                  style={[
                    styles.icon,
                    { backgroundColor: server.color + "33", borderColor: server.color + "55" },
                    active && {
                      backgroundColor: server.color + "55",
                      borderColor: server.color,
                    },
                  ]}
                >
                  <Text style={[styles.iconText, { color: server.color }]}>
                    {server.initials}
                  </Text>
                </View>
                <View style={styles.meta}>
                  <Text numberOfLines={1} style={styles.name}>
                    {isDm ? "Direct messages" : server.name}
                  </Text>
                  <Text style={styles.sub}>
                    {isDm ? "DMs · groups" : "tap to open"}
                  </Text>
                </View>
                {server.unread ? (
                  <View style={styles.badge}>
                    <Text style={styles.badgeText}>{server.unread}</Text>
                  </View>
                ) : null}
              </Pressable>
            );
          })}

          <Pressable style={({ pressed }) => [styles.addRow, pressed && { opacity: 0.7 }]}>
            <View style={styles.addIcon}>
              <Text style={styles.addPlus}>+</Text>
            </View>
            <Text style={styles.addLabel}>Add server</Text>
          </Pressable>
        </ScrollView>
      </Island>
    </View>
  );
};

const styles = StyleSheet.create({
  wrap: { flex: 1, paddingHorizontal: spacing.md, paddingBottom: spacing.md },
  island: { flex: 1 },
  heading: {
    color: colors.textMd,
    fontSize: 11,
    letterSpacing: 1.5,
    fontWeight: "700",
    marginBottom: spacing.md,
    textTransform: "uppercase",
  },
  list: { paddingBottom: spacing.lg, gap: 6 },
  row: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
    paddingVertical: spacing.sm,
    paddingRight: spacing.md,
    borderRadius: radii.lg,
  },
  rowActive: {
    backgroundColor: "rgba(124,107,245,0.10)",
  },
  bar: {
    width: 3,
    height: 24,
    borderRadius: 2,
    backgroundColor: "transparent",
  },
  barActive: { backgroundColor: colors.primary },
  icon: {
    width: 46,
    height: 46,
    borderRadius: radii.lg,
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 1,
  },
  iconText: { fontSize: 16, fontWeight: "700" },
  meta: { flex: 1, minWidth: 0 },
  name: { color: colors.textHi, fontSize: 14, fontWeight: "600" },
  sub: { color: colors.textLo, fontSize: 11, marginTop: 1 },
  badge: {
    minWidth: 22,
    height: 22,
    paddingHorizontal: 6,
    borderRadius: radii.pill,
    backgroundColor: colors.primary,
    alignItems: "center",
    justifyContent: "center",
  },
  badgeText: { color: "#fff", fontSize: 11, fontWeight: "700" },
  addRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
    paddingVertical: spacing.sm,
    paddingRight: spacing.md,
    marginTop: spacing.sm,
  },
  addIcon: {
    width: 46,
    height: 46,
    marginLeft: 3,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    borderStyle: "dashed",
    alignItems: "center",
    justifyContent: "center",
  },
  addPlus: { color: colors.textMd, fontSize: 22, marginTop: -2 },
  addLabel: { color: colors.textMd, fontSize: 13 },
});
