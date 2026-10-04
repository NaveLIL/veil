/**
 * Source adaptation: Rocket.Chat.ReactNative 4.77.0 / 0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36.
 * app/views/NewMessageView/Item.tsx.
 * Copyright (c) 2015-2018 Rocket.Chat Technologies Corp. MIT.
 * Changes: controlled contact/disabled props, local avatar slot; remove VoIP/SDK.
 * See third-party/rocket-chat-reactnative/SOURCE_INVENTORY.md.
 */
import React, { type ReactNode } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { rocketColors, rocketText } from "./theme";

export function ContactItem({ name, avatar, disabled, onPress }: {
  name: string;
  avatar: ReactNode;
  disabled: boolean;
  onPress: () => void;
}) {
  return (
    <Pressable
      testID="contact-result"
      onPress={onPress}
      disabled={disabled}
      accessibilityLabel={`Start Direct with ${name}`}
      accessibilityRole="button"
      accessibilityState={{ disabled }}
      style={({ pressed }) => [styles.button, pressed && styles.pressed]}
    >
      <View style={styles.container}>
        <View style={styles.avatar}>{avatar}</View>
        <View style={styles.textContainer}>
          <Text style={styles.name} numberOfLines={1}>{name}</Text>
        </View>
      </View>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  button: { minHeight: 54, backgroundColor: rocketColors.surfaceLight },
  pressed: { backgroundColor: rocketColors.surfaceSelected },
  container: { flexDirection: "row", minHeight: 54 },
  avatar: { marginHorizontal: 12, marginVertical: 12 },
  textContainer: { flex: 1, flexDirection: "column", justifyContent: "center", marginRight: 12 },
  name: { fontSize: 18, lineHeight: 26, ...rocketText, fontWeight: "500", color: rocketColors.fontDefault },
});
