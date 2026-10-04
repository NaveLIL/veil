import React from "react";
import { ActivityIndicator, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import { Search, X } from "lucide-react-native";
import { useNavigation } from "@react-navigation/native";
import type { NativeStackNavigationProp } from "@react-navigation/native-stack";
import type { DesignPreviewStackParamList } from "../../designPreview/navigation";
import { useContactsPresenter } from "../../presenters/contacts";
import { ContactItem } from "../../presentation/rocketChat/ContactItem";
import { UserAvatar } from "../identity/UserAvatar";
import { PublicFailureCard } from "../runtime/PublicFailureCard";
import { colors, radii, spacing } from "../../lib/theme";

/** Preview wrapper uses the same native contact authority as the production screen. */
export function InlineContactSearch({ onExit }: { onExit: () => void }) {
  const navigation = useNavigation<NativeStackNavigationProp<DesignPreviewStackParamList>>();
  const p = useContactsPresenter((conversationId) => {
    onExit();
    navigation.navigate("Direct", { conversationId });
  });
  const busy = p.status === "searching" || p.status === "creating";
  return (
    <View>
      <View style={styles.panel}>
        <TextInput style={styles.input} placeholder="Exact username..." placeholderTextColor={colors.textLo}
          accessibilityLabel="Exact username" value={p.query} onChangeText={p.setQuery} editable={p.available}
          autoCapitalize="none" autoCorrect={false} returnKeyType="search" onSubmitEditing={() => void p.search()} />
        <Pressable accessibilityRole="button" accessibilityLabel="Search username"
          disabled={!p.available || !p.query.trim() || busy} onPress={() => void p.search()} style={styles.action}>
          <Search size={20} color={colors.textLo} />
        </Pressable>
        <Pressable accessibilityRole="button" accessibilityLabel="Close contact search" onPress={onExit} style={styles.action}>
          <X size={20} color={colors.textLo} />
        </Pressable>
      </View>
      <View style={styles.results}>
        {busy ? <ActivityIndicator color={colors.textHi} /> : null}
        {p.status === "error" ? <PublicFailureCard code="VEIL-RUNTIME-999" compact /> : p.result ? (
          <ContactItem name={p.result.username} disabled={busy} onPress={() => void p.create()}
            avatar={<UserAvatar canonicalServerOrigin={p.binding?.canonicalServerOrigin ?? ""}
              userId={p.result.userId} technicalUsername={p.result.username} size={30} />} />
        ) : !busy ? <Text style={styles.hint}>{p.status === "not_found"
          ? "No user found with that exact username." : "Enter an exact username to search."}</Text> : null}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  panel: { minHeight: 56, backgroundColor: colors.surfaceSolid, borderRadius: radii.xl,
    paddingLeft: spacing.lg, flexDirection: "row", alignItems: "center" },
  input: { flex: 1, minHeight: 48, color: colors.textHi, fontSize: 16, padding: 0 },
  action: { minWidth: 48, minHeight: 48, alignItems: "center", justifyContent: "center" },
  results: { marginTop: 12 },
  hint: { color: colors.textLo, fontSize: 14, textAlign: "center", padding: spacing.xl },
});
