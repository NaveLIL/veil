/**
 * Source adaptation: Rocket.Chat.ReactNative 4.77.0 / 0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36.
 * MessageComposerContent.tsx, ComposerInput.tsx, Buttons/BaseButton.tsx, constants.ts.
 * Copyright (c) 2015-2018 Rocket.Chat Technologies Corp. MIT.
 * Changes: controlled text/async acceptance controller outside presentation;
 * remove autosave, uploads, autocomplete, audio, threads and Rocket context;
 * existing Lucide icon and Pressable replace custom font/gesture button.
 * See third-party/rocket-chat-reactnative/SOURCE_INVENTORY.md.
 */
import React from "react";
import { ActivityIndicator, Pressable, StyleSheet, TextInput, View } from "react-native";
import { Send } from "lucide-react-native";
import { rocketColors, rocketText } from "./theme";

export function Composer({ value, onChangeText, editable, pending, onSend }: {
  value: string;
  onChangeText: (value: string) => void;
  editable: boolean;
  pending: boolean;
  onSend: () => void;
}) {
  const canSend = editable && value.length > 0 && !pending;
  return (
    <View testID="rocket-composer" style={styles.container}>
      <View style={styles.inputRow}>
        <TextInput
          testID="direct-composer"
          value={value}
          onChangeText={onChangeText}
          editable={editable && !pending}
          accessibilityLabel="Direct message"
          accessibilityState={{ disabled: !editable || pending }}
          placeholder={editable ? "Message securely" : "Direct messaging unavailable"}
          placeholderTextColor={rocketColors.fontAnnotation}
          style={styles.textInput}
          underlineColorAndroid="transparent"
          multiline
          keyboardAppearance="dark"
        />
        <Pressable
          testID="direct-send-button"
          onPress={onSend}
          disabled={!canSend}
          accessibilityRole="button"
          accessibilityLabel="Send Direct message"
          accessibilityState={{ disabled: !canSend, busy: pending }}
          style={({ pressed }) => [styles.button, !canSend && styles.disabled, pressed && styles.pressed]}
        >
          {pending ? <ActivityIndicator color={rocketColors.strokeHighlight} /> : <Send size={24} color={rocketColors.strokeHighlight} />}
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { borderTopWidth: 1, paddingHorizontal: 16, minHeight: 48, backgroundColor: rocketColors.surfaceLight, borderTopColor: rocketColors.strokeLight },
  inputRow: { flexDirection: "row", alignItems: "flex-end" },
  textInput: { flex: 1, minHeight: 48, maxHeight: 200, paddingTop: 12, paddingBottom: 12, fontSize: 16, textAlignVertical: "center", ...rocketText, lineHeight: 22, color: rocketColors.fontDefault },
  button: { minWidth: 48, minHeight: 48, alignItems: "center", justifyContent: "center" },
  disabled: { opacity: 0.38 },
  pressed: { opacity: 0.72 },
});
