import React from 'react';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { AccountRouteSurface } from '../presentation/account/AccountRouteSurface';
import type { AuthenticatedStackParamList } from '../presentation/account/routes';
import { SettingsContent } from '../presentation/settings/SettingsContent';
import { SETTINGS_SECTIONS } from '../presentation/settings/definitions';

export default function SettingsScreen({ navigation }: NativeStackScreenProps<AuthenticatedStackParamList, 'Settings'>) {
  return <AccountRouteSurface testID="settings-screen" title="Настройки" subtitle="Veil на этом устройстве" onBack={() => navigation.goBack()}>
    <SettingsContent testID="settings-root-scroll" onSection={section => navigation.push('SettingsDetail', { section })} />
  </AccountRouteSurface>;
}
export function SettingsDetailScreen({ navigation, route }: NativeStackScreenProps<AuthenticatedStackParamList, 'SettingsDetail'>) {
  const item = SETTINGS_SECTIONS.find(s => s.key === route.params.section)!;
  return <AccountRouteSurface testID={`settings-${item.key}`} title={item.title} subtitle={item.summary} onBack={() => navigation.goBack()}>
    <SettingsContent testID="settings-detail-scroll" section={item.key} onSection={section => navigation.push('SettingsDetail', { section })} />
  </AccountRouteSurface>;
}
