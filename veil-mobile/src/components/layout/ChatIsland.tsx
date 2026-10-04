/**
 * Source adaptation: Rocket.Chat.ReactNative 4.77.0 / 0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36.
 * app/views/RoomView/List/components/List.tsx (FlatList layout/tuning).
 * Copyright (c) 2015-2018 Rocket.Chat Technologies Corp. MIT.
 * Changes: native bounded projection, Veil identity/delivery and composer slots;
 * remove Rocket history loaders, database subscriptions, gestures and model stores.
 * See third-party/rocket-chat-reactnative/SOURCE_INVENTORY.md.
 */
import React, { useEffect, useRef } from "react";
import { FlatList, KeyboardAvoidingView, Platform, Pressable, StyleSheet, Text, View } from "react-native";
import { type Member, type Message as ProjectedMessage } from "../../stores/chat";
import { useDirectTimelinePresenter } from "../../presenters/directTimeline";
import { Composer } from "../../presentation/rocketChat/Composer";
import { Message } from "../../presentation/rocketChat/Message";
import { rocketColors } from "../../presentation/rocketChat/theme";
import { UserAvatar } from "../identity/UserAvatar";
import { PublicFailureCard } from "../runtime/PublicFailureCard";

/**
 * Veil controller + Rocket.Chat source-ported Direct presentation.
 * FlatList layout follows Rocket.Chat 4.77.0 RoomView/List/components/List.tsx;
 * native owns the bounded window. No Rocket history loaders or model observers.
 */
export const ChatIsland: React.FC<{
  bottomInset?: number;
  leftInset?: number;
  onOpenIdentity?: (member: Member, triggerHandle: string | number) => void;
  rightInset?: number;
  showHeader?: boolean;
}> = ({ bottomInset = 0, leftInset = 0, onOpenIdentity, rightInset = 0, showHeader = true }) => {
  const p = useDirectTimelinePresenter();
  const list = useRef<FlatList<ProjectedMessage>>(null);
  const followsNewest = useRef(true);
  const viewportOffset = useRef(0);
  useEffect(() => { followsNewest.current = true; viewportOffset.current = 0; }, [p.scope]);
  const empty = !p.conversationId
    ? ["Choose a Direct conversation", "Encrypted history opens only after selection."]
    : p.projectionState === "loading" || p.projectionState === "idle"
      ? ["Opening encrypted history...", "Verifying this conversation with the native runtime."]
      : p.projectionState === "unavailable"
        ? ["Messages are unavailable", "Veil withheld the entire projection because it could not be verified."]
        : ["No messages yet", "This immutable Direct history is securely synchronized."];

  return (
    <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === "ios" ? "padding" : undefined}>
      <View
        testID="chat-island-wrap"
        style={[styles.wrap, {
          paddingBottom: 12 + Math.max(0, bottomInset),
          paddingLeft: Math.max(12, leftInset),
          paddingRight: Math.max(12, rightInset),
        }]}
      >
        {showHeader ? <View style={styles.header}><Text style={styles.title}>{p.title}</Text></View> : null}
        <FlatList
          ref={list}
          testID="direct-message-list"
          data={p.messages}
          keyExtractor={(message) => `${p.scope ?? "unavailable"}\u0000${message.stableUiId}`}
          style={styles.flex}
          contentContainerStyle={styles.messages}
          keyboardShouldPersistTaps="handled"
          initialNumToRender={20}
          maxToRenderPerBatch={5}
          windowSize={10}
          scrollEventThrottle={32}
          onScroll={({ nativeEvent: { contentOffset, contentSize, layoutMeasurement } }) => {
            // Native invalidation clears plaintext during verification. Its empty
            // layout must not overwrite the reader's transient viewport position.
            if (p.projectionState !== "available" || p.messages.length === 0) return;
            viewportOffset.current = Math.max(0, contentOffset.y);
            followsNewest.current = contentSize.height - layoutMeasurement.height - contentOffset.y <= 96;
          }}
          onContentSizeChange={() => {
            if (p.projectionState !== "available" || p.messages.length === 0) return;
            if (followsNewest.current) list.current?.scrollToEnd({ animated: false });
            else list.current?.scrollToOffset({ offset: viewportOffset.current, animated: false });
          }}
          ListEmptyComponent={(
            <View
              testID={p.conversationId && (p.projectionState === "loading" || p.projectionState === "idle")
                ? "direct-history-loading" : p.projectionState === "unavailable" ? "direct-history-unavailable" : undefined}
              style={styles.empty}
            >
              <Text style={styles.emptyTitle}>{empty[0]}</Text>
              <Text style={styles.emptyHint}>{empty[1]}</Text>
              {p.projectionState === "unavailable" ? (
                <Pressable accessibilityRole="button" onPress={() => void p.reload()} style={styles.retry}>
                  <Text style={styles.retryText}>Verify again</Text>
                </Pressable>
              ) : null}
            </View>
          )}
          renderItem={({ item: message }) => (
            <Message
              renderKey={message.stableUiId}
              authorName={message.author.name}
              text={message.text}
              timestamp={message.timestampMs === null ? null : message.ts}
              onOpenIdentity={(event) => onOpenIdentity?.(message.author, event.nativeEvent.target)}
              avatar={<UserAvatar
                identityKey={message.author.identityKey}
                canonicalServerOrigin={message.author.canonicalServerOrigin}
                userId={message.author.userId}
                technicalUsername={message.author.username}
                size={36}
              />}
              delivery={message.direction === "outgoing" && message.deliveryPublicFailureCodeV1 ? (
                <View testID={`direct-delivery-failure-${message.stableUiId}`} style={styles.deliveryFailure}>
                  <PublicFailureCard announce={false} code={message.deliveryPublicFailureCodeV1} compact />
                </View>
              ) : message.direction === "outgoing" && message.delivery !== "sent" ? (
                <Text style={styles.delivery}>{message.delivery}</Text>
              ) : null}
            />
          )}
        />
        <Composer value={p.draft} onChangeText={p.setDraft} editable={p.canCompose} pending={p.pending} onSend={() => void p.sendDraft()} />
        {p.error ? <View testID="direct-send-error" style={styles.sendError}><PublicFailureCard code={p.error.publicFailureCodeV1} compact /></View> : null}
      </View>
    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  flex: { flex: 1 },
  wrap: { flex: 1, backgroundColor: rocketColors.surfaceRoom },
  header: { padding: 12, borderBottomWidth: StyleSheet.hairlineWidth, borderColor: rocketColors.strokeLight },
  title: { color: rocketColors.fontTitlesLabels, fontSize: 17, fontWeight: "600" },
  messages: { paddingTop: 10, flexGrow: 1 },
  empty: { flex: 1, alignItems: "center", justifyContent: "center", padding: 24 },
  emptyTitle: { color: rocketColors.fontTitlesLabels, fontSize: 16, textAlign: "center" },
  emptyHint: { color: rocketColors.fontSecondaryInfo, fontSize: 14, lineHeight: 22, marginTop: 8, textAlign: "center" },
  retry: { minHeight: 48, justifyContent: "center", paddingHorizontal: 16 },
  retryText: { color: rocketColors.strokeHighlight, fontSize: 16, fontWeight: "600" },
  delivery: { color: rocketColors.fontSecondaryInfo, fontSize: 12 },
  deliveryFailure: { maxWidth: 420 },
  sendError: { paddingHorizontal: 16, paddingBottom: 8 },
});
