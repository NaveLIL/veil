import React from "react";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { StatusBar } from "expo-status-bar";
import { NavigationContainer, DefaultTheme } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";

import OnboardingScreen from "./src/screens/OnboardingScreen";
import ChatListScreen from "./src/screens/ChatListScreen";
import { useAuthStore } from "./src/stores/auth";

const Stack = createNativeStackNavigator();

const navTheme = {
  ...DefaultTheme,
  dark: true,
  colors: {
    ...DefaultTheme.colors,
    background: "#111117",
    card: "#111117",
    primary: "#7c6bf5",
    text: "#ededf0",
    border: "rgba(255,255,255,0.06)",
    notification: "#7c6bf5",
  },
};

export default function App() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);

  return (
    <GestureHandlerRootView style={{ flex: 1, backgroundColor: "#111117" }}>
      <SafeAreaProvider>
        <NavigationContainer theme={navTheme}>
          <StatusBar style="light" translucent />
          <Stack.Navigator
            screenOptions={{
              headerShown: false,
              contentStyle: { backgroundColor: "#111117" },
              animation: "fade",
              animationDuration: 320,
            }}
          >
            {!isAuthenticated ? (
              <Stack.Screen name="Onboarding" component={OnboardingScreen} />
            ) : (
              <Stack.Screen name="ChatList" component={ChatListScreen} />
            )}
          </Stack.Navigator>
        </NavigationContainer>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}
