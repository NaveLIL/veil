import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";

import { colors, radii, spacing } from "../../lib/theme";
import { DM_HOME_ID, type Member, useChatStore } from "../../stores/chat";
import { UserAvatar } from "../identity/UserAvatar";
import { Island } from "../ui/Island";

const EMPTY_MESSAGES: never[] = [];

export const ChatIsland: React.FC<{
  bottomInset?: number;
  leftInset?: number;
  onOpenIdentity?: (member: Member, triggerHandle: string | number) => void;
  rightInset?: number;
  showHeader?: boolean;
}> = ({
  bottomInset = 0,
  leftInset = 0,
  onOpenIdentity,
  rightInset = 0,
  showHeader = true,
}) => {
  const selectedServerId = useChatStore((state) => state.selectedServerId);
  const selectedChannelId = useChatStore((state) => state.selectedChannelId);
  const selectedDmId = useChatStore((state) => state.selectedDmId);
  const messagesByChannel = useChatStore((state) => state.messagesByChannel);
  const projectionStateByConversation = useChatStore(
    (state) => state.projectionStateByConversation,
  );
  const directoryRevision = useChatStore((state) => state.directoryRevision);
  const channels = useChatStore((state) => state.channels);
  const dms = useChatStore((state) => state.dms);
  const loadSelectedDirectMessages = useChatStore(
    (state) => state.loadSelectedDirectMessages,
  );
  const directGeneration = useChatStore((state) => state.directGeneration);
  const directSendPending = useChatStore((state) => state.directSendPending);
  const directSendError = useChatStore((state) => state.directSendError);
  const sendSelectedDirectText = useChatStore((state) => state.sendSelectedDirectText);
  const [draft, setDraft] = useState("");

  const key = selectedServerId === DM_HOME_ID ? selectedDmId : selectedChannelId;
  const messages = key ? messagesByChannel[key] ?? EMPTY_MESSAGES : EMPTY_MESSAGES;
  const projectionState = selectedDmId
    ? projectionStateByConversation[selectedDmId] ?? "idle"
    : "idle";
  const title = useMemo(() => {
    if (selectedServerId === DM_HOME_ID) {
      return dms.find((dm) => dm.id === selectedDmId)?.name ?? "Direct messages";
    }
    const channel = channels.find((candidate) => candidate.id === selectedChannelId);
    return channel ? `# ${channel.name}` : "Channel";
  }, [selectedServerId, selectedDmId, selectedChannelId, dms, channels]);
  const scrollRef = useRef<ScrollView>(null);
  const canCompose = selectedServerId === DM_HOME_ID
    && selectedDmId !== null
    && directGeneration !== null
    && projectionState === "available"
    && !directSendPending;
  const canSend = canCompose && draft.length > 0;

  useEffect(() => {
    if (selectedServerId !== DM_HOME_ID || !selectedDmId) return;
    void loadSelectedDirectMessages();
  }, [
    directoryRevision,
    loadSelectedDirectMessages,
    selectedDmId,
    selectedServerId,
  ]);

  useEffect(() => {
    requestAnimationFrame(() => scrollRef.current?.scrollToEnd({ animated: false }));
  }, [messages.length]);

  useEffect(() => {
    // A draft must never follow the user to another peer or Direct generation.
    setDraft("");
  }, [directGeneration, selectedDmId]);

  const sendDraft = async () => {
    if (!canSend) return;
    const submitted = draft;
    const submittedConversationId = selectedDmId;
    const submittedGeneration = directGeneration;
    const result = await sendSelectedDirectText(submitted);
    const current = useChatStore.getState();
    if (
      result === "accepted"
      && current.selectedDmId === submittedConversationId
      && current.directGeneration === submittedGeneration
    ) {
      setDraft((current) => current === submitted ? "" : current);
    }
  };

  return (
    <View
      testID="chat-island-wrap"
      style={[
        styles.wrap,
        {
          paddingBottom: spacing.md + Math.max(0, bottomInset),
          paddingLeft: Math.max(spacing.md, leftInset),
          paddingRight: Math.max(spacing.md, rightInset),
        },
      ]}
    >
      <Island variant="solid" glow={false} padding={0} style={styles.island}>
        {showHeader ? (
          <View style={styles.header}>
            <Text numberOfLines={1} style={styles.title}>{title}</Text>
            <Text style={styles.headerHint}>Direct conversation</Text>
          </View>
        ) : null}

        <ScrollView
          ref={scrollRef}
          style={styles.scroller}
          contentContainerStyle={styles.messages}
          onContentSizeChange={() => scrollRef.current?.scrollToEnd({ animated: true })}
        >
          {!selectedDmId ? (
            <View style={styles.empty}>
              <Text style={styles.emptyText}>Choose a Direct conversation</Text>
              <Text style={styles.emptyHint}>Encrypted history opens only after selection.</Text>
            </View>
          ) : projectionState === "loading" || projectionState === "idle" ? (
            <View testID="direct-history-loading" style={styles.empty}>
              <Text style={styles.emptyText}>Opening encrypted history...</Text>
              <Text style={styles.emptyHint}>Verifying this conversation with the native runtime.</Text>
            </View>
          ) : projectionState === "unavailable" ? (
            <View testID="direct-history-unavailable" style={styles.empty}>
              <Text style={styles.emptyText}>Messages are unavailable</Text>
              <Text style={styles.emptyHint}>
                Veil withheld the entire projection because it could not be verified.
              </Text>
              <Pressable
                accessibilityRole="button"
                onPress={() => void loadSelectedDirectMessages()}
                style={({ pressed }) => [styles.retry, pressed && styles.retryPressed]}
              >
                <Text style={styles.retryText}>Verify again</Text>
              </Pressable>
            </View>
          ) : messages.length === 0 ? (
            <View style={styles.empty}>
              <Text style={styles.emptyText}>No messages yet</Text>
              <Text style={styles.emptyHint}>This immutable Direct history is securely synchronized.</Text>
            </View>
          ) : (
            messages.map((message) => (
              <View key={message.id} style={styles.messageRow}>
                <Pressable
                  accessibilityRole="button"
                  accessibilityLabel={`View identity for ${message.author.name}`}
                  onPress={(event) => onOpenIdentity?.(message.author, event.nativeEvent.target)}
                  style={styles.identityTrigger}
                >
                  <UserAvatar
                    identityKey={message.author.identityKey}
                    canonicalServerOrigin={message.author.canonicalServerOrigin}
                    userId={message.author.userId}
                    technicalUsername={message.author.username}
                    size={36}
                  />
                </Pressable>
                <View style={styles.messageBody}>
                  <View style={styles.messageHead}>
                    <Text style={[styles.author, { color: message.author.color }]}>
                      {message.author.name}
                    </Text>
                    <Text style={styles.timestamp}>{message.ts}</Text>
                  </View>
                  <Text style={styles.text}>{message.text}</Text>
                  {message.direction === "outgoing" && message.delivery !== "sent" ? (
                    <Text style={styles.delivery}>{message.delivery}</Text>
                  ) : null}
                </View>
              </View>
            ))
          )}
        </ScrollView>

        <View style={styles.composer}>
          <TextInput
            testID="direct-composer"
            value={draft}
            onChangeText={setDraft}
            editable={canCompose}
            accessibilityLabel="Direct message"
            accessibilityState={{ disabled: !canCompose }}
            placeholder={canCompose ? "Message securely" : "Direct messaging unavailable"}
            placeholderTextColor={colors.textLo}
            style={styles.input}
            multiline
          />
          <Pressable
            testID="direct-send-button"
            accessibilityRole="button"
            accessibilityLabel="Send Direct message"
            accessibilityState={{ disabled: !canSend }}
            disabled={!canSend}
            onPress={() => void sendDraft()}
            style={({ pressed }) => [
              styles.sendButton,
              !canSend && styles.sendButtonDisabled,
              pressed && canSend && styles.sendButtonPressed,
            ]}
          >
            <Text style={styles.sendButtonText}>{directSendPending ? "..." : "Send"}</Text>
          </Pressable>
        </View>
        {directSendError ? (
          <Text testID="direct-send-error" style={styles.sendError}>
            {directSendError === "rejected"
              ? "Message was rejected"
              : "Direct messaging is unavailable"}
          </Text>
        ) : null}
      </Island>
    </View>
  );
};

const styles = StyleSheet.create({
  wrap: { flex: 1 },
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
  scroller: { flex: 1 },
  messages: { padding: spacing.md, gap: spacing.md, flexGrow: 1 },
  empty: { flex: 1, alignItems: "center", justifyContent: "center", paddingTop: 80 },
  emptyText: { color: colors.textMd, fontSize: 14, textAlign: "center" },
  emptyHint: {
    color: colors.textLo,
    fontSize: 12,
    lineHeight: 18,
    marginTop: 4,
    maxWidth: 300,
    textAlign: "center",
  },
  retry: {
    minHeight: 48,
    alignItems: "center",
    justifyContent: "center",
    borderRadius: radii.pill,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    paddingHorizontal: spacing.lg,
    marginTop: spacing.md,
  },
  retryPressed: { opacity: 0.72 },
  retryText: { color: colors.primaryHi, fontSize: 12, fontWeight: "700" },
  messageRow: { flexDirection: "row", gap: spacing.sm },
  identityTrigger: { minWidth: 48, minHeight: 48, alignItems: "center", justifyContent: "center" },
  messageBody: { flex: 1, minWidth: 0 },
  messageHead: { flexDirection: "row", alignItems: "baseline", gap: spacing.sm },
  author: { fontSize: 13, fontWeight: "700" },
  timestamp: { color: colors.textLo, fontSize: 10 },
  text: { color: colors.textHi, fontSize: 14, lineHeight: 20, marginTop: 2 },
  delivery: {
    color: colors.textLo,
    fontSize: 10,
    marginTop: 4,
    textTransform: "uppercase",
    letterSpacing: 0.8,
  },
  composer: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    padding: spacing.sm,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: colors.border,
  },
  input: {
    flex: 1,
    color: colors.textHi,
    fontSize: 13,
    minHeight: 48,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    borderRadius: radii.lg,
    backgroundColor: "rgba(255,255,255,0.04)",
  },
  sendButton: {
    minWidth: 48,
    minHeight: 48,
    paddingHorizontal: spacing.sm,
    borderRadius: radii.pill,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    backgroundColor: colors.primary,
    alignItems: "center",
    justifyContent: "center",
  },
  sendButtonDisabled: { opacity: 0.38 },
  sendButtonPressed: { opacity: 0.72 },
  sendButtonText: {
    color: colors.textHi,
    fontSize: 11,
    fontWeight: "800",
  },
  sendError: {
    color: colors.destructive,
    fontSize: 11,
    paddingHorizontal: spacing.md,
    paddingBottom: spacing.sm,
  },
});
