import React, { useEffect, useMemo } from "react";
import { DarkTheme, NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";

import { useReducedMotionPreference } from "../hooks/useReducedMotionPreference";
import { useChatStore } from "../stores/chat";
import DirectConversationScreen from "./DirectConversationScreen";
import HomeScreen from "./HomeScreen";
import ContactSearchScreen from "./ContactSearchScreen";
import SettingsScreen, { SettingsDetailScreen } from "./SettingsScreen";
import { usePresentation } from '../interfacePreview/PresentationContext';

import type { AuthenticatedStackParamList } from '../presentation/account/routes';
export type { AuthenticatedStackParamList, SettingsSectionKey } from '../presentation/account/routes';

const Stack = createNativeStackNavigator<AuthenticatedStackParamList>();

/**
 * Authenticated mobile shell.
 *
 * Runtime/bootstrap authority stays outside NavigationContainer in App.tsx.
 * This stack only receives already verified projections and is deliberately
 * reset whenever the authenticated origin/account/generation changes.
 */
export default function ChatListScreen() {
  const { c } = usePresentation();
  const theme = useMemo(() => ({...DarkTheme, colors:{...DarkTheme.colors,
    primary:c.accent, background:c.bg, card:c.bg, text:c.text, border:c.line, notification:c.accent}}), [c]);
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
    <NavigationContainer key={navigationScope} theme={theme}>
      <Stack.Navigator
        initialRouteName="Home"
        screenOptions={{
          animation: reducedMotion ? "none" : "slide_from_right",
          contentStyle: { backgroundColor: c.bg },
          headerShown: false,
        }}
      >
        <Stack.Screen name="Home" component={HomeScreen} />
        <Stack.Screen name="Contacts" component={ContactSearchScreen} />
        <Stack.Screen name="Direct" component={DirectConversationScreen} />
        <Stack.Screen name="Settings" component={SettingsScreen} />
        <Stack.Screen name="SettingsDetail" component={SettingsDetailScreen} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
