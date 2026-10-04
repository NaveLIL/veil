/**
 * Source adaptation: Rocket.Chat.ReactNative 4.77.0 / 0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36.
 * app/views/RoomsListView/index.tsx (FlatList/empty/loading presentation).
 * Copyright (c) 2015-2018 Rocket.Chat Technologies Corp. MIT.
 * Changes: native Direct directory, scoped Veil selection and typed navigation;
 * no Rocket subscriptions, sorting preferences, workspace/preview routes.
 * See third-party/rocket-chat-reactnative/SOURCE_INVENTORY.md.
 */
import React from "react";
import { FlatList, Pressable, StyleSheet, Text, View } from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";
import { Settings2, SquarePen } from "lucide-react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { UserAvatar } from "../components/identity/UserAvatar";
import { MobileHeader } from "../components/navigation/MobileHeader";
import { RoomItem } from "../presentation/rocketChat/RoomItem";
import { rocketColors } from "../presentation/rocketChat/theme";
import { useChatStore } from "../stores/chat";
import type { AuthenticatedStackParamList } from "./ChatListScreen";

type Props = NativeStackScreenProps<AuthenticatedStackParamList, "Home">;

export default function HomeScreen({ navigation }: Props) {
  const insets = useSafeAreaInsets();
  const dms = useChatStore((s) => s.dms);
  const selectedDmId = useChatStore((s) => s.selectedDmId);
  const binding = useChatStore((s) => s.runtimeBinding);
  const generation = useChatStore((s) => s.directGeneration);
  const openDirect = (conversationId: string) => {
    const current = useChatStore.getState();
    if (!binding || current.runtimeBinding?.canonicalServerOrigin !== binding.canonicalServerOrigin
      || current.runtimeBinding.userId !== binding.userId || current.directGeneration !== generation) return;
    current.selectDm(conversationId);
    if (useChatStore.getState().selectedDmId === conversationId) navigation.navigate("Direct", { conversationId });
  };

  return (
    <View testID="home-screen" style={styles.root}>
      <MobileHeader showBrand title="Home" subtitle="Direct messages" action={{
        label: "Settings", accessibilityLabel: "Open Settings", icon: Settings2,
        onPress: () => navigation.navigate("Settings"),
      }} />
      <View style={[styles.content, { paddingLeft: insets.left, paddingRight: insets.right }]}>
        <Pressable testID="open-contact-search" accessibilityRole="button" accessibilityLabel="Find contacts"
          onPress={() => navigation.navigate("Contacts")} style={styles.newDirect}>
          <SquarePen size={22} color={rocketColors.strokeHighlight} />
          <Text style={styles.newDirectText}>New Direct conversation</Text>
        </Pressable>
        <FlatList
          testID="direct-directory-list"
          data={dms}
          keyExtractor={(dm) => `${binding?.canonicalServerOrigin ?? ""}\u0000${binding?.userId ?? ""}\u0000${dm.id}`}
          contentContainerStyle={{ flexGrow: 1, paddingBottom: insets.bottom + 12 }}
          initialNumToRender={12}
          windowSize={9}
          keyboardShouldPersistTaps="always"
          ListEmptyComponent={<View style={styles.empty}>
            <Text style={styles.emptyTitle}>No Direct conversations yet</Text>
            <Text style={styles.emptyHint}>Find someone by their exact username to start a conversation.</Text>
          </View>}
          renderItem={({ item: dm }) => <RoomItem conversationId={dm.id} name={dm.name} selected={selectedDmId === dm.id}
            onPress={() => openDirect(dm.id)} avatar={<UserAvatar canonicalServerOrigin={dm.avatarIdentity.canonicalServerOrigin}
              userId={dm.avatarIdentity.userId} technicalUsername={dm.avatarIdentity.username} size={36} />} />}
        />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: rocketColors.surfaceRoom },
  content: { flex: 1 },
  newDirect: { flexDirection: "row", gap: 12, alignItems: "center", paddingHorizontal: 16, minHeight: 56,
    borderBottomWidth: StyleSheet.hairlineWidth, borderColor: rocketColors.strokeLight },
  newDirectText: { color: rocketColors.fontTitlesLabels, fontSize: 16, flexShrink: 1 },
  empty: { flex: 1, alignItems: "center", justifyContent: "center", padding: 24 },
  emptyTitle: { color: rocketColors.fontTitlesLabels, fontSize: 18, textAlign: "center" },
  emptyHint: { color: rocketColors.fontSecondaryInfo, fontSize: 14, lineHeight: 22, textAlign: "center", marginTop: 8 },
});
