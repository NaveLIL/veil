/**
 * Source adaptation: Rocket.Chat.ReactNative 4.77.0 / 0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36.
 * app/containers/RoomItem/{RoomItem,Wrapper,Title,styles}.tsx (styles.ts).
 * Copyright (c) 2015-2018 Rocket.Chat Technologies Corp. MIT.
 * Changes: narrow DTO/callback props; Veil local avatar slot; native metadata only;
 * remove Rocket stores, swipe actions, presence, unread and last-message inference.
 * See third-party/rocket-chat-reactnative/SOURCE_INVENTORY.md.
 */
import React, { memo, type ReactNode } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { rocketColors, rocketText } from "./theme";

interface Props {
  conversationId: string;
  name: string;
  avatar: ReactNode;
  selected: boolean;
  onPress: () => void;
}

export const RoomItem = memo(function RoomItem({ conversationId, name, avatar, selected, onPress }: Props) {
  return (
    <Pressable
      testID={`direct-list-item-${conversationId}`}
      accessibilityRole="button"
      accessibilityLabel={`Open Direct with ${name}`}
      accessibilityState={{ selected }}
      onPress={onPress}
      style={({ pressed }) => [styles.touchable, (pressed || selected) && styles.selected]}
    >
      <View style={styles.container}>
        <View style={styles.avatar}>{avatar}</View>
        <View style={styles.centerContainer}>
          <View style={styles.titleContainer}>
            <Text style={styles.title} ellipsizeMode="tail" numberOfLines={1}>{name}</Text>
          </View>
        </View>
      </View>
    </Pressable>
  );
});

const styles = StyleSheet.create({
  touchable: { backgroundColor: rocketColors.surfaceRoom, minHeight: 64 },
  selected: { backgroundColor: rocketColors.surfaceSelected },
  container: { flexDirection: "row", alignItems: "center", paddingLeft: 14, minHeight: 64 },
  avatar: { marginRight: 10 },
  centerContainer: {
    flex: 1, paddingVertical: 10, paddingRight: 14,
    borderBottomWidth: StyleSheet.hairlineWidth, borderColor: rocketColors.strokeLight,
  },
  titleContainer: { width: "100%", flexDirection: "row", alignItems: "center", justifyContent: "center" },
  title: { flex: 1, fontSize: 17, ...rocketText, fontWeight: "500", color: rocketColors.fontTitlesLabels },
});
