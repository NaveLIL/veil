import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  KeyboardAvoidingView,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { Island } from "../ui/Island";
import { colors, radii, spacing } from "../../lib/theme";
import { DM_HOME_ID, useChatStore } from "../../stores/chat";

const EMPTY_MSGS: never[] = [];

export const ChatIsland: React.FC = () => {
  const selectedServerId = useChatStore((s) => s.selectedServerId);
  const selectedChannelId = useChatStore((s) => s.selectedChannelId);
  const selectedDmId = useChatStore((s) => s.selectedDmId);
  const messagesByChannel = useChatStore((s) => s.messagesByChannel);
  const channels = useChatStore((s) => s.channels);
  const dms = useChatStore((s) => s.dms);
  const sendMessage = useChatStore((s) => s.sendMessage);

  const key = selectedServerId === DM_HOME_ID ? selectedDmId : selectedChannelId;
  const messages = key ? messagesByChannel[key] ?? EMPTY_MSGS : EMPTY_MSGS;
  const title = useMemo(() => {
    if (selectedServerId === DM_HOME_ID) {
      return dms.find((d) => d.id === selectedDmId)?.name ?? "Direct messages";
    }
    const ch = channels.find((c) => c.id === selectedChannelId);
    return ch ? `# ${ch.name}` : "Channel";
  }, [selectedServerId, selectedDmId, selectedChannelId, dms, channels]);
  const [draft, setDraft] = useState("");
  const scrollRef = useRef<ScrollView>(null);

  useEffect(() => {
    requestAnimationFrame(() => scrollRef.current?.scrollToEnd({ animated: false }));
  }, [messages.length]);

  const onSend = () => {
    const t = draft.trim();
    if (!t) return;
    sendMessage(t);
    setDraft("");
  };

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === "ios" ? "padding" : undefined}
      style={styles.wrap}
    >
      <Island padding={0} style={styles.island}>
        <View style={styles.header}>
          <Text numberOfLines={1} style={styles.title}>{title}</Text>
          <Text style={styles.headerHint}>swipe ◀ channels · members ▶</Text>
        </View>

        <ScrollView
          ref={scrollRef}
          style={{ flex: 1 }}
          contentContainerStyle={styles.messages}
          onContentSizeChange={() => scrollRef.current?.scrollToEnd({ animated: true })}
        >
          {messages.length === 0 ? (
            <View style={styles.empty}>
              <Text style={styles.emptyText}>No messages yet</Text>
              <Text style={styles.emptyHint}>Be the first to write something ✨</Text>
            </View>
          ) : (
            messages.map((m) => (
              <View key={m.id} style={styles.msgRow}>
                <View style={[styles.avatar, { backgroundColor: m.authorColor + "33", borderColor: m.authorColor + "55" }]}>
                  <Text style={[styles.avatarText, { color: m.authorColor }]}>
                    {m.authorName.charAt(0).toUpperCase()}
                  </Text>
                </View>
                <View style={styles.msgBody}>
                  <View style={styles.msgHead}>
                    <Text style={[styles.author, { color: m.authorColor }]}>{m.authorName}</Text>
                    <Text style={styles.ts}>{m.ts}</Text>
                  </View>
                  <Text style={styles.text}>{m.text}</Text>
                </View>
              </View>
            ))
          )}
        </ScrollView>

        <View style={styles.composer}>
          <TextInput
            value={draft}
            onChangeText={setDraft}
            placeholder="Message…"
            placeholderTextColor={colors.textLo}
            style={styles.input}
            multiline
            onSubmitEditing={onSend}
            blurOnSubmit
          />
          <Pressable
            onPress={onSend}
            disabled={!draft.trim()}
            style={({ pressed }) => [
              styles.sendBtn,
              !draft.trim() && { opacity: 0.4 },
              pressed && { opacity: 0.7 },
            ]}
          >
            <Text style={styles.sendText}>↑</Text>
          </Pressable>
        </View>
      </Island>
    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  wrap: { flex: 1, paddingHorizontal: spacing.md, paddingBottom: spacing.md },
  island: { flex: 1 },
  header: {
    paddingHorizontal: spacing.md,
    paddingTop: spacing.md,
    paddingBottom: spacing.sm,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: colors.border,
  },
  title: { color: colors.textHi, fontSize: 16, fontWeight: "700" },
  headerHint: { color: colors.textLo, fontSize: 10, marginTop: 2 },

  messages: { padding: spacing.md, gap: spacing.md, flexGrow: 1 },

  empty: { flex: 1, alignItems: "center", justifyContent: "center", paddingTop: 80 },
  emptyText: { color: colors.textMd, fontSize: 14 },
  emptyHint: { color: colors.textLo, fontSize: 12, marginTop: 4 },

  msgRow: { flexDirection: "row", gap: spacing.sm },
  avatar: {
    width: 36,
    height: 36,
    borderRadius: radii.pill,
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 1,
  },
  avatarText: { fontSize: 14, fontWeight: "700" },
  msgBody: { flex: 1, minWidth: 0 },
  msgHead: { flexDirection: "row", alignItems: "baseline", gap: spacing.sm },
  author: { fontSize: 13, fontWeight: "700" },
  ts: { color: colors.textLo, fontSize: 10 },
  text: { color: colors.textHi, fontSize: 14, lineHeight: 20, marginTop: 2 },

  composer: {
    flexDirection: "row",
    alignItems: "flex-end",
    gap: spacing.sm,
    padding: spacing.sm,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: colors.border,
  },
  input: {
    flex: 1,
    color: colors.textHi,
    fontSize: 14,
    minHeight: 40,
    maxHeight: 120,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    borderRadius: radii.lg,
    backgroundColor: "rgba(255,255,255,0.04)",
  },
  sendBtn: {
    width: 40,
    height: 40,
    borderRadius: radii.pill,
    backgroundColor: colors.primary,
    alignItems: "center",
    justifyContent: "center",
  },
  sendText: { color: "#fff", fontSize: 18, fontWeight: "700" },
});
