import React from "react";
import { StatusBar } from "expo-status-bar";
import { NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";
import OnboardingScreen from "./src/screens/OnboardingScreen";
import ChatListScreen from "./src/screens/ChatListScreen";
import { useAuthStore } from "./src/stores/auth";

const Stack = createNativeStackNavigator();

export default function App() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);

  return (
    <NavigationContainer>
      <StatusBar style="light" />
      <Stack.Navigator
        screenOptions={{
          headerShown: false,
          contentStyle: { backgroundColor: "#0a0a0f" },
          animation: "fade",
        }}
      >
        {!isAuthenticated ? (
          <Stack.Screen name="Onboarding" component={OnboardingScreen} />
        ) : (
          <Stack.Screen name="ChatList" component={ChatListScreen} />
        )}
      </Stack.Navigator>
    </NavigationContainer>
  );
}
