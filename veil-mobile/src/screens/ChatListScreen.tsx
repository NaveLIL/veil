import React from "react";
import { View, Text, StyleSheet } from "react-native";
import { useAuthStore } from "../stores/auth";

export default function ChatListScreen() {
  const identityKey = useAuthStore((s) => s.identityKey);

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.logo}>VEIL</Text>
      </View>
      <View style={styles.empty}>
        <Text style={styles.emptyText}>No conversations yet</Text>
      </View>
      <View style={styles.footer}>
        <Text style={styles.footerText}>
          {identityKey?.slice(0, 16)}...
        </Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#0a0a0f" },
  header: {
    paddingVertical: 16,
    paddingHorizontal: 20,
    borderBottomWidth: 1,
    borderBottomColor: "#1a1a25",
  },
  logo: { color: "#6366f1", fontSize: 13, letterSpacing: 4 },
  empty: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
  },
  emptyText: { color: "#444" },
  footer: {
    paddingVertical: 12,
    paddingHorizontal: 20,
    borderTopWidth: 1,
    borderTopColor: "#1a1a25",
  },
  footerText: { color: "#555", fontSize: 12, fontFamily: "monospace" },
});
