import React from "react";
import { StyleSheet, Text, View } from "react-native";

import { colors, spacing } from "../../lib/theme";
import { type Member, useChatStore } from "../../stores/chat";
import { Island } from "../ui/Island";

export const MembersIsland: React.FC<{
  onOpenIdentity?: (member: Member, triggerHandle: string | number) => void;
}> = () => {
  const selectedDmId = useChatStore((state) => state.selectedDmId);
  const dm = useChatStore((state) =>
    state.dms.find((candidate) => candidate.id === selectedDmId),
  );

  return (
    <View style={styles.wrap}>
      <Island padding={spacing.md} style={styles.island}>
        <Text style={styles.title}>Details</Text>
        <Text style={styles.sub}>direct conversation</Text>
        <View style={styles.details}>
          <Text style={styles.detailTitle}>{dm?.name ?? "No conversation selected"}</Text>
          {dm ? (
            <>
              <Text style={styles.username}>@{dm.peerUsername}</Text>
              <View style={styles.divider} />
              <Text style={styles.label}>Peer account</Text>
              <Text selectable style={styles.account}>{dm.peerUserId}</Text>
              <View style={styles.divider} />
            </>
          ) : null}
          <Text style={styles.secureTitle}>End-to-end encrypted</Text>
          <Text style={styles.body}>
            Immutable Direct text is opened only through the verified native runtime. Veil clears
            renderable history when the app backgrounds, reconnects or loses runtime authority.
          </Text>
          <View style={styles.divider} />
          <Text style={styles.hint}>Attachments · edits · sending coming in later preview stages</Text>
        </View>
      </Island>
    </View>
  );
};

const styles = StyleSheet.create({
  wrap: { flex: 1, paddingHorizontal: spacing.md, paddingBottom: spacing.md },
  island: { flex: 1 },
  title: { color: colors.textHi, fontSize: 18, fontWeight: "700" },
  sub: {
    color: colors.textLo,
    fontSize: 11,
    marginTop: 2,
    marginBottom: spacing.md,
    textTransform: "uppercase",
    letterSpacing: 1.5,
  },
  details: { flex: 1, paddingTop: spacing.lg },
  detailTitle: { color: colors.textHi, fontSize: 18, fontWeight: "800" },
  username: { color: colors.textLo, fontSize: 12, marginTop: 3 },
  label: {
    color: colors.textLo,
    fontSize: 10,
    fontWeight: "700",
    letterSpacing: 1.2,
    textTransform: "uppercase",
  },
  account: {
    color: colors.textMd,
    fontFamily: "monospace",
    fontSize: 11,
    lineHeight: 17,
    marginTop: 5,
  },
  secureTitle: { color: colors.textHi, fontSize: 15, fontWeight: "700" },
  body: { color: colors.textMd, fontSize: 12, lineHeight: 18, marginTop: spacing.sm },
  divider: {
    height: StyleSheet.hairlineWidth,
    backgroundColor: colors.border,
    marginVertical: spacing.lg,
  },
  hint: { color: colors.textLo, fontSize: 11, lineHeight: 17 },
});
