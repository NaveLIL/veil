/**
 * Source adaptation: Rocket.Chat.ReactNative 4.77.0 / 0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36.
 * Copyright (c) 2015-2018 Rocket.Chat Technologies Corp. MIT.
 * Exact native search retained; presentation migrated to shared Veil.
 * See third-party/rocket-chat-reactnative/SOURCE_INVENTORY.md.
 */
import React, { useCallback, useEffect, useRef } from 'react';
import { FlatList, Keyboard, Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { Search, ChevronRight } from 'lucide-react-native';
import { AccountRouteSurface } from '../presentation/account/AccountRouteSurface';
import { KeyboardFrame } from '../interfacePreview/KeyboardFrame';
import { usePresentation } from '../interfacePreview/PresentationContext';
import { geometry, typography } from '../interfacePreview/appearance';
import { VeilState } from '../interfacePreview/VeilState';
import { UserAvatar } from '../components/identity/UserAvatar';
import { contactsCopy as copy } from '../presentation/copy/contacts';
import { useContactsPresenter } from '../presenters/contacts';
import { useAccountNavigation } from '../presentation/account/useAccountNavigation';
import { useChatStore } from '../stores/chat';
import type { AuthenticatedStackParamList } from '../presentation/account/routes';

export default function ContactSearchScreen({ navigation }: NativeStackScreenProps<AuthenticatedStackParamList, 'Contacts'>) {
  const { c } = usePresentation();
  const opened = useRef<{ id: string; peer: string; origin: string; userId: string; generation: number } | null>(null);
  const opening = useRef(false);
  useEffect(() => navigation.addListener?.('focus', () => { opening.current = false; }), [navigation]);
  const navigateToDirect = useCallback((id: string) => {
    if (opening.current || (navigation.isFocused && !navigation.isFocused())) return;
    opening.current = true;
    Keyboard.dismiss(); navigation.push('Direct', { conversationId: id });
  }, [navigation]);
  const select = useAccountNavigation(navigateToDirect);
  const p = useContactsPresenter(id => {
    const s = useChatStore.getState(), dm = s.dms.find(item => item.id === id);
    if (s.runtimeBinding && s.directGeneration !== null && dm) opened.current = { id, peer: dm.avatarIdentity.userId,
      origin: s.runtimeBinding.canonicalServerOrigin, userId: s.runtimeBinding.userId, generation: s.directGeneration };
    navigateToDirect(id);
  });
  const busy = p.status === 'searching' || p.status === 'creating';
  const openResult = () => {
    if (opening.current || busy || (navigation.isFocused && !navigation.isFocused())) return;
    const s = useChatStore.getState(), last = opened.current;
    if (last && last.peer === p.result?.userId && last.origin === s.runtimeBinding?.canonicalServerOrigin
      && last.userId === s.runtimeBinding?.userId && last.generation === s.directGeneration
      && s.dms.some(dm => dm.id === last.id && dm.avatarIdentity.userId === last.peer)) select(last.id);
    else void p.create();
  };
  return <KeyboardFrame><AccountRouteSurface testID="contact-search-screen" title={copy.title} subtitle={copy.subtitle} onBack={() => navigation.goBack()}>
    <View style={styles.content}>
      <View style={[styles.search, { backgroundColor: c.surface, borderColor: c.line }]}>
        <TextInput testID="contact-username" value={p.query} onChangeText={p.setQuery} accessibilityLabel={copy.username}
          placeholder={copy.username} placeholderTextColor={c.muted} autoCapitalize="none" autoCorrect={false}
          returnKeyType="search" editable={p.available} onSubmitEditing={() => void p.search()}
          style={[styles.input, { color: c.text }]} />
        <Pressable testID="contact-search-submit" accessibilityRole="button" accessibilityLabel={copy.submit}
          accessibilityState={{ disabled: !p.available || !p.query.trim() || busy, busy }}
          disabled={!p.available || !p.query.trim() || busy} onPress={() => void p.search()} style={styles.submit}>
          <Search accessible={false} size={22} color={c.accent} />
        </Pressable>
      </View>
      <Text style={[styles.hint, { color: c.muted }]}>{copy.hint}</Text>
      <FlatList testID="contact-results-list" data={p.result && !busy && p.available ? [p.result] : []}
        keyExtractor={contact => contact.userId} keyboardShouldPersistTaps="handled" keyboardDismissMode="on-drag"
        contentContainerStyle={styles.results} renderItem={({ item }) => <Pressable accessibilityRole="button"
          accessibilityLabel={copy.open(item.username)} disabled={busy} accessibilityState={{ disabled: busy }}
          onPress={openResult} style={({ pressed }) => [styles.result, { backgroundColor: c.surface }, pressed && { opacity: 0.7 }]}>
          {p.binding && <UserAvatar canonicalServerOrigin={p.binding.canonicalServerOrigin} userId={item.userId} technicalUsername={item.username} size={44} />}
          <View style={styles.meta}><Text style={[styles.name, { color: c.text }]}>{item.username}</Text>
            <Text style={[styles.hint, { color: c.muted }]}>Личный чат · проверка личности отдельно</Text></View>
          <ChevronRight accessible={false} color={c.muted} size={20} />
        </Pressable>}
        ListEmptyComponent={<VeilState c={c} kind={!p.available ? 'unavailable' : busy ? 'loading' : p.status === 'error' ? 'error' : 'empty'}
          testID={!p.available ? 'contact-unavailable' : busy ? 'contact-operation-pending' : p.status === 'error' ? 'contact-public-error' : p.status === 'not_found' ? 'contact-not-found' : 'contact-search-empty'}
          title={!p.available ? copy.unavailable : p.status === 'creating' ? copy.creating : busy ? copy.loading : p.status === 'error' ? copy.error : p.status === 'not_found' ? copy.missing : copy.empty}
          detail={!p.available ? copy.unavailableDetail : p.status === 'creating' ? copy.creatingDetail : busy ? copy.loadingDetail : p.status === 'error' ? copy.errorDetail : p.status === 'not_found' ? copy.missingDetail : copy.emptyDetail}
          action={p.available && p.status === 'error' && p.query.trim() ? { label: copy.retry, onPress: () => void p.search() } : undefined} />} />
    </View>
  </AccountRouteSurface></KeyboardFrame>;
}
const styles = StyleSheet.create({
  content: { flex: 1, padding: 12, gap: 12 }, search: { flexDirection: 'row', alignItems: 'center', borderRadius: geometry.radius, borderWidth: geometry.borderWidth },
  input: { ...typography.body, flex: 1, minWidth: 0, minHeight: geometry.touchTarget, padding: 12 },
  submit: { minWidth: geometry.touchTarget, minHeight: geometry.touchTarget, alignItems: 'center', justifyContent: 'center' },
  hint: { ...typography.caption }, results: { flexGrow: 1, paddingBottom: 24 },
  result: { minHeight: geometry.touchTarget, padding: 12, borderRadius: geometry.radius, flexDirection: 'row', gap: 12, alignItems: 'center' },
  meta: { flex: 1, minWidth: 0 }, name: { ...typography.body, fontWeight: '600' },
});
