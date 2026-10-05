import React, { useCallback, useEffect, useRef, useState } from "react";
import { AccessibilityInfo, BackHandler, Keyboard, StyleSheet, View } from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";

import { IdentityIslandSheet } from "../components/identity/IdentityIslandSheet";
import { ChatIsland } from "../components/layout/ChatIsland";
import { AccountFrame } from '../presentation/account/AccountFrame';
import { useAccountNavigation } from '../presentation/account/useAccountNavigation';
import { usePresentation } from '../interfacePreview/PresentationContext';
import { VeilState } from '../interfacePreview/VeilState';
import { type Member, useChatStore } from "../stores/chat";
import type { AuthenticatedStackParamList } from "../presentation/account/routes";

type Props = NativeStackScreenProps<AuthenticatedStackParamList, "Direct">;

export default function DirectConversationScreen({ navigation, route }: Props) {
  const { c } = usePresentation();
  const [navigationOpen, setNavigationOpen] = useState(false);
  const selected = useCallback((conversationId: string) => {
    navigation.setParams({ conversationId }); setNavigationOpen(false);
  }, [navigation]);
  const onOpen = useAccountNavigation(selected);
  useEffect(() => {
    const subscription = BackHandler.addEventListener('hardwareBackPress', () => {
      if (navigation.isFocused && !navigation.isFocused()) return false;
      if (navigationOpen) return false;
      Keyboard.dismiss(); setNavigationOpen(true); return true;
    });
    return () => subscription.remove();
  }, [navigation, navigationOpen]);
  const conversationId = route.params.conversationId;
  const conversation = useChatStore((state) =>
    state.dms.find((candidate) => candidate.id === conversationId),
  );
  const selectedDmId = useChatStore((state) => state.selectedDmId);
  const directGeneration = useChatStore((state) => state.directGeneration);
  const [identitySelection, setIdentitySelection] = useState<{
    conversationId: string;
    profile: Member;
  } | null>(null);
  const identityReturnFocusHandle = useRef<number | null>(null);
  const focusFrame = useRef<number | null>(null);
  const routeReady = Boolean(conversation && selectedDmId === conversationId);
  const identityProfile = routeReady
    && identitySelection?.conversationId === conversationId
    ? identitySelection.profile
    : null;

  useEffect(() => {
    const restoreRoute = () => {
      if (navigation.isFocused && !navigation.isFocused()) return;
      const state = useChatStore.getState();
      if (!state.dms.some(dm => dm.id === conversationId)) { navigation.goBack(); return; }
      if (state.selectedDmId !== conversationId) {
        if (!state.dms.some(dm => dm.id === state.selectedDmId)) { navigation.goBack(); return; }
        state.selectDm(conversationId);
      }
    };
    restoreRoute();
    const unsubscribe = navigation.addListener?.('focus', restoreRoute);
    return unsubscribe;
  }, [navigation, conversationId, directGeneration]);

  useEffect(() => {
    setIdentitySelection(null);
    identityReturnFocusHandle.current = null;
    if (focusFrame.current !== null) cancelAnimationFrame(focusFrame.current);
    focusFrame.current = null;
    return () => { if (focusFrame.current !== null) cancelAnimationFrame(focusFrame.current); };
  }, [routeReady, conversationId, directGeneration]);

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
      focusFrame.current = requestAnimationFrame(() => {
        focusFrame.current = null;
        AccessibilityInfo.setAccessibilityFocus(handle);
      });
    }
  }, []);

  return (
    <View testID="direct-screen" style={[styles.root, {backgroundColor:c.bg}]}>
      <AccountFrame onOpen={onOpen} onContacts={() => navigation.navigate('Contacts')}
        navigationOpen={navigationOpen}
        onNavigationChange={setNavigationOpen} modalOpen={!!identityProfile}
        conversation={<View
        style={styles.content}
        importantForAccessibility={identityProfile ? "no-hide-descendants" : "auto"}
        pointerEvents={identityProfile ? "none" : "auto"}
      >
        {routeReady ? (
          <ChatIsland
            embedded
            onBack={() => { Keyboard.dismiss(); setNavigationOpen(true); }}
            onOpenIdentity={openIdentity}
            showHeader
          />
        ) : (
          <VeilState testID="direct-route-pending" c={c} kind="unavailable"
            title="Личный чат недоступен" detail="Диалог не подтверждён в текущей сессии аккаунта." />
        )}
      </View>} />
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
  root: { flex: 1 },
  content: { flex: 1 },
});
