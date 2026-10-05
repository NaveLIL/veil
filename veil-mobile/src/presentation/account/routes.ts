/** Route identity is presentation state; native/account authority lives outside this stack. */
export type SettingsSectionKey = 'account' | 'devices' | 'privacy' | 'notifications' | 'appearance' | 'node' | 'storage' | 'about';
export type AuthenticatedStackParamList = {
  Home: undefined;
  Contacts: undefined;
  Direct: { conversationId: string };
  Settings: undefined;
  SettingsDetail: { section: SettingsSectionKey };
};
