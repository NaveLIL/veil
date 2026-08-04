import React, { useEffect } from "react";
import { DarkTheme, NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";

import { useReducedMotionPreference } from "../hooks/useReducedMotionPreference";
import { colors } from "../lib/theme";
import { useChatStore } from "../stores/chat";
import DirectConversationScreen from "./DirectConversationScreen";
import DesignPreviewHomeScreen from "../designPreview/DesignPreviewHomeScreen";
import {
  DesignCircleScreen,
  DesignSpaceScreen,
  DesignRoomScreen,
} from "../designPreview/DesignPreviewScreens";
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
  DesignCircle: undefined;
  DesignSpace: undefined;
  DesignRoom: { roomId: string };
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
        <Stack.Screen name="Home" component={DesignPreviewHomeScreen as any} />
        <Stack.Screen name="Direct" component={DirectConversationScreen} />
        <Stack.Screen name="Settings" component={SettingsScreen} />
        <Stack.Screen name="SettingsDetail" component={SettingsDetailScreen} />
        <Stack.Screen name="DesignCircle" component={DesignCircleScreen as any} />
        <Stack.Screen name="DesignSpace" component={DesignSpaceScreen as any} />
        <Stack.Screen name="DesignRoom" component={DesignRoomScreen as any} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
