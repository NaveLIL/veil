import React, { useCallback } from 'react';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { AccountFrame } from '../presentation/account/AccountFrame';
import { useAccountNavigation } from '../presentation/account/useAccountNavigation';
import type { AuthenticatedStackParamList } from './ChatListScreen';

export default function HomeScreen({ navigation }: NativeStackScreenProps<AuthenticatedStackParamList, 'Home'>) {
  const selected = useCallback((conversationId: string) => navigation.navigate('Direct', { conversationId }), [navigation]);
  const onOpen = useAccountNavigation(selected);
  return <AccountFrame testID="home-screen" onOpen={onOpen}
    onContacts={() => navigation.navigate('Contacts')} onSettings={() => navigation.navigate('Settings')} />;
}
