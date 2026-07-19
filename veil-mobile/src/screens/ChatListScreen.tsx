import React, { useEffect } from "react";
import { DarkTheme, NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";

import { useReducedMotionPreference } from "../hooks/useReducedMotionPreference";
import { colors } from "../lib/theme";
import { useChatStore } from "../stores/chat";
import DirectConversationScreen from "./DirectConversationScreen";
import HomeScreen from "./HomeScreen";
import SettingsScreen, { SettingsDetailScreen } from "./SettingsScreen";

export type SettingsSectionKey =
  | "account"
  | "devices"
  | "privacy"
  | "notifications"
  | "appearance"
  | "node"
  | "storage"
  | "about";

export type AuthenticatedStackParamList = {
  Home: undefined;
  Direct: { conversationId: string };
  Settings: undefined;
  SettingsDetail: { section: SettingsSectionKey };
};

const Stack = createNativeStackNavigator<AuthenticatedStackParamList>();

const VEIL_NAVIGATION_THEME = {
  ...DarkTheme,
  colors: {
    ...DarkTheme.colors,
    primary: colors.primary,
    background: colors.background,
    card: colors.surfaceSolid,
    text: colors.textHi,
    border: colors.border,
    notification: colors.primaryHi,
  },
};

/**
 * Authenticated mobile shell.
 *
 * Runtime/bootstrap authority stays outside NavigationContainer in App.tsx.
 * This stack only receives already verified projections and is deliberately
 * reset whenever the authenticated origin/account/generation changes.
 */
export default function ChatListScreen() {
  const reducedMotion = useReducedMotionPreference();
  const runtimeBinding = useChatStore((state) => state.runtimeBinding);
  const directGeneration = useChatStore((state) => state.directGeneration);
  const navigationScope = runtimeBinding && directGeneration !== null
    ? `${runtimeBinding.canonicalServerOrigin}\u0000${runtimeBinding.userId}\u0000${directGeneration}`
    : "unavailable";

  useEffect(() => () => {
    // Runtime gates unmount this shell for reconnect, errors and privacy.
    // Do not leave an old binding's plaintext renderable in the JS heap.
    useChatStore.getState().clearRenderableChat();
  }, []);

  return (
    <NavigationContainer key={navigationScope} theme={VEIL_NAVIGATION_THEME}>
      <Stack.Navigator
        initialRouteName="Home"
        screenOptions={{
          animation: reducedMotion ? "none" : "slide_from_right",
          contentStyle: { backgroundColor: colors.background },
          headerShown: false,
        }}
      >
        <Stack.Screen name="Home" component={HomeScreen} />
        <Stack.Screen name="Direct" component={DirectConversationScreen} />
        <Stack.Screen name="Settings" component={SettingsScreen} />
        <Stack.Screen name="SettingsDetail" component={SettingsDetailScreen} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
