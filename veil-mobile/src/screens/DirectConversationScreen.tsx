import React, { useCallback, useEffect, useRef, useState } from "react";
import { AccessibilityInfo, StyleSheet, Text, View } from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { IdentityIslandSheet } from "../components/identity/IdentityIslandSheet";
import { ChatIsland } from "../components/layout/ChatIsland";
import { MobileHeader } from "../components/navigation/MobileHeader";
import { colors, spacing } from "../lib/theme";
import { type Member, useChatStore } from "../stores/chat";
import type { AuthenticatedStackParamList } from "./ChatListScreen";

type Props = NativeStackScreenProps<AuthenticatedStackParamList, "Direct">;

export default function DirectConversationScreen({ navigation, route }: Props) {
  const insets = useSafeAreaInsets();
  const conversationId = route.params.conversationId;
  const conversation = useChatStore((state) =>
    state.dms.find((candidate) => candidate.id === conversationId),
  );
  const peer = useChatStore(
    (state) => state.directMembersByConversation[conversationId]?.peer ?? null,
  );
  const selectedDmId = useChatStore((state) => state.selectedDmId);
  const directGeneration = useChatStore((state) => state.directGeneration);
  const [identitySelection, setIdentitySelection] = useState<{
    conversationId: string;
    profile: Member;
  } | null>(null);
  const identityReturnFocusHandle = useRef<number | null>(null);
  const routeReady = Boolean(conversation && selectedDmId === conversationId);
  const identityProfile = routeReady
    && identitySelection?.conversationId === conversationId
    ? identitySelection.profile
    : null;

  useEffect(() => {
    if (!routeReady) navigation.goBack();
  }, [navigation, routeReady]);

  useEffect(() => {
    if (routeReady) return;
    setIdentitySelection(null);
    identityReturnFocusHandle.current = null;
  }, [routeReady]);

  const openIdentity = useCallback((profile: Member, triggerHandle: string | number) => {
    const handle = Number(triggerHandle);
    identityReturnFocusHandle.current = Number.isSafeInteger(handle) && handle > 0
      ? handle
      : null;
    setIdentitySelection({ conversationId, profile });
  }, [conversationId]);

  const closeIdentity = useCallback(() => {
    setIdentitySelection(null);
    const handle = identityReturnFocusHandle.current;
    identityReturnFocusHandle.current = null;
    if (handle) {
      requestAnimationFrame(() => AccessibilityInfo.setAccessibilityFocus(handle));
    }
  }, []);

  return (
    <View testID="direct-screen" style={styles.root}>
      <View
        style={styles.content}
        importantForAccessibility={identityProfile ? "no-hide-descendants" : "auto"}
        pointerEvents={identityProfile ? "none" : "auto"}
      >
        <MobileHeader
          title={routeReady ? conversation?.name ?? "Direct" : "Direct"}
          subtitle={routeReady ? "End-to-end encrypted" : "Selection unavailable"}
          backAction={{
            label: "Home",
            onPress: () => navigation.goBack(),
          }}
          action={routeReady && peer ? {
            label: "Details",
            onPress: (event) => openIdentity(peer, event.nativeEvent.target),
          } : undefined}
        />
        {routeReady ? (
          <ChatIsland
            bottomInset={insets.bottom}
            leftInset={insets.left}
            rightInset={insets.right}
            onOpenIdentity={openIdentity}
            showHeader={false}
          />
        ) : (
          <View
            testID="direct-route-pending"
            accessibilityRole="alert"
            accessibilityLabel="Direct conversation unavailable"
            style={styles.routePending}
          >
            <Text style={styles.routePendingText}>
              This Direct conversation is unavailable.
            </Text>
          </View>
        )}
      </View>
      <IdentityIslandSheet
        profile={identityProfile}
        contextLabel="Direct conversation"
        returnLabel="Direct"
        directVerification={identityProfile && directGeneration !== null ? {
          conversationId,
          directGeneration,
        } : undefined}
        onClose={closeIdentity}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  content: { flex: 1 },
  routePending: { flex: 1, alignItems: "center", justifyContent: "center", padding: spacing.xxl },
  routePendingText: { color: colors.textMd, fontSize: 13, marginTop: spacing.md, textAlign: "center" },
});
