/**
 * Source adaptation: Rocket.Chat.ReactNative 4.77.0 / 0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36.
 * app/views/NewMessageView/index.tsx, HeaderNewMessage.tsx, containers/SearchBox/index.tsx.
 * Copyright (c) 2015-2018 Rocket.Chat Technologies Corp. MIT.
 * Changes: exact-username native controller, Veil runtime gate/header, explicit search;
 * remove local DB/spotlight, Rocket create/navigation/VoIP and renderer HTTP.
 * See third-party/rocket-chat-reactnative/SOURCE_INVENTORY.md.
 */
import React from "react";
import { ActivityIndicator, FlatList, KeyboardAvoidingView, Platform, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";
import { Search } from "lucide-react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { MobileHeader } from "../components/navigation/MobileHeader";
import { UserAvatar } from "../components/identity/UserAvatar";
import { PublicFailureCard } from "../components/runtime/PublicFailureCard";
import { ContactItem } from "../presentation/rocketChat/ContactItem";
import { rocketColors } from "../presentation/rocketChat/theme";
import { useContactsPresenter } from "../presenters/contacts";
import type { AuthenticatedStackParamList } from "./ChatListScreen";

type Props = NativeStackScreenProps<AuthenticatedStackParamList, "Contacts">;

export default function ContactSearchScreen({ navigation }: Props) {
  const insets = useSafeAreaInsets();
  const p = useContactsPresenter((conversationId) => navigation.replace("Direct", { conversationId }));
  const busy = p.status === "searching" || p.status === "creating";
  return (
    <KeyboardAvoidingView testID="contact-search-screen" style={styles.root} behavior={Platform.OS === "ios" ? "padding" : undefined}>
      <MobileHeader title="New Direct" subtitle="Find someone by username"
        backAction={{ label: "Home", onPress: () => navigation.goBack() }} />
      <View style={[styles.content, { paddingLeft: insets.left, paddingRight: insets.right }]}>
        <View style={styles.inputContainer}>
          <TextInput testID="contact-username" style={styles.input} value={p.query} onChangeText={p.setQuery}
            accessibilityLabel="Exact username" placeholder="Exact username" placeholderTextColor={rocketColors.fontAnnotation}
            autoCapitalize="none" autoCorrect={false} returnKeyType="search" underlineColorAndroid="transparent"
            editable={p.available} onSubmitEditing={() => void p.search()} />
          <Pressable testID="contact-search-submit" accessibilityRole="button" accessibilityLabel="Search username"
            accessibilityState={{ disabled: !p.available || !p.query.trim() || busy, busy }}
            disabled={!p.available || !p.query.trim() || busy} onPress={() => void p.search()} style={styles.searchButton}>
            <Search size={22} color={rocketColors.strokeHighlight} />
          </Pressable>
        </View>
        <Text style={styles.hint}>Use the exact username on this Node.</Text>
        <FlatList
          data={p.result ? [p.result] : []}
          testID="contact-results-list"
          keyExtractor={(contact) => contact.userId}
          contentContainerStyle={{ flexGrow: 1, paddingBottom: insets.bottom + 12 }}
          keyboardShouldPersistTaps="always"
          renderItem={({ item: contact }) => <ContactItem name={contact.username} disabled={busy}
            onPress={() => void p.create()} avatar={<UserAvatar canonicalServerOrigin={p.binding?.canonicalServerOrigin ?? ""}
              userId={contact.userId} technicalUsername={contact.username} size={30} />} />}
          ListFooterComponent={busy ? <View testID="contact-operation-pending" style={styles.status}>
            <ActivityIndicator color={rocketColors.strokeHighlight} /><Text style={styles.statusText}>
              {p.status === "creating" ? "Opening Direct..." : "Searching..."}</Text>
          </View> : null}
          ListEmptyComponent={!busy ? <View style={styles.status}>
            {p.status === "error" ? <View testID="contact-public-error"><PublicFailureCard code="VEIL-RUNTIME-999" compact /></View>
              : <Text testID={p.status === "not_found" ? "contact-not-found" : "contact-search-empty"} style={styles.statusText}>
                {p.status === "not_found" ? "No user found with that exact username." : "Enter a username to find someone."}
              </Text>}
          </View> : null}
        />
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: rocketColors.surfaceRoom },
  content: { flex: 1 },
  inputContainer: { marginHorizontal: 12, marginTop: 16, marginBottom: 16, flexDirection: "row",
    alignItems: "center", borderWidth: 1, borderColor: rocketColors.strokeLight, borderRadius: 4 },
  input: { flex: 1, minHeight: 48, paddingHorizontal: 12, color: rocketColors.fontDefault, fontSize: 16 },
  searchButton: { minWidth: 48, minHeight: 48, justifyContent: "center", alignItems: "center" },
  hint: { color: rocketColors.fontSecondaryInfo, fontSize: 13, marginHorizontal: 12, marginBottom: 16 },
  status: { padding: 24, alignItems: "center", gap: 12 },
  statusText: { color: rocketColors.fontSecondaryInfo, fontSize: 16, lineHeight: 22, textAlign: "center" },
});
