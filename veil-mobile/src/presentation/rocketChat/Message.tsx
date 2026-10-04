/**
 * Source adaptation: Rocket.Chat.ReactNative 4.77.0 / 0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36.
 * FullMessage.tsx, User.tsx, Time.tsx, message/styles.ts, markdown/Plain.tsx/styles.ts.
 * Copyright (c) 2015-2018 Rocket.Chat Technologies Corp. MIT.
 * Changes: explicit transient DTO/slots replace Rocket message/room stores;
 * bounded plain text; Veil identity/delivery slots; no fabricated timestamp/status.
 * See third-party/rocket-chat-reactnative/SOURCE_INVENTORY.md.
 */
import React, { memo, type ReactNode } from "react";
import { Pressable, StyleSheet, Text, View, type GestureResponderEvent } from "react-native";
import { rocketColors, rocketText } from "./theme";

interface Props {
  renderKey: string;
  authorName: string;
  text: string;
  timestamp: string | null;
  avatar: ReactNode;
  delivery: ReactNode;
  onOpenIdentity: (event: GestureResponderEvent) => void;
}

export const Message = memo(function Message({ renderKey, authorName, text, timestamp, avatar, delivery, onOpenIdentity }: Props) {
  return (
    <View testID={`message-${renderKey}`} style={styles.container}>
      <View style={styles.flex}>
        <Pressable
          accessibilityRole="button"
          accessibilityLabel={`View identity for ${authorName}`}
          onPress={onOpenIdentity}
          style={styles.avatar}
        >{avatar}</Pressable>
        <View style={styles.messageContent}>
          <View style={styles.userContainer}>
            <View style={styles.titleContainer}>
              <Text style={styles.username} numberOfLines={1}>{authorName}</Text>
              {timestamp ? <Text style={styles.time}>{timestamp}</Text> : null}
            </View>
          </View>
          <View style={{ gap: 4 }}>
            <Text accessibilityLabel={text} style={styles.plainText}>{text}</Text>
            {delivery}
          </View>
        </View>
      </View>
    </View>
  );
});

const styles = StyleSheet.create({
  container: { paddingVertical: 4, width: "100%", paddingHorizontal: 12, flexDirection: "column", gap: 8 },
  flex: { flexDirection: "row" },
  avatar: { marginTop: 4, minWidth: 48, minHeight: 48, alignItems: "center", justifyContent: "center" },
  messageContent: { flex: 1, marginLeft: 10, minWidth: 0 },
  userContainer: { flex: 1, flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  titleContainer: { flexShrink: 1, flexDirection: "row", alignItems: "center", flexWrap: "wrap", gap: 4 },
  username: { flexShrink: 1, fontSize: 16, lineHeight: 22, ...rocketText, fontWeight: "600", color: rocketColors.fontTitlesLabels },
  time: { fontSize: 13, lineHeight: 18, ...rocketText, color: rocketColors.fontSecondaryInfo },
  plainText: { fontSize: 16, flexShrink: 1, lineHeight: 22, color: rocketColors.fontDefault },
});
