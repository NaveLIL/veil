import React, { useEffect } from "react";
import { ActivityIndicator, Text, View } from "react-native";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { StatusBar } from "expo-status-bar";
import { NavigationContainer, DefaultTheme } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";

import OnboardingScreen from "./src/screens/OnboardingScreen";
import ChatListScreen from "./src/screens/ChatListScreen";
import { useAuthStore } from "./src/stores/auth";
import VeilCrypto from "./src/native/crypto";

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
  const nativeIdentityState = useAuthStore((s) => s.nativeIdentityState);
  const setLocalIdentityReady = useAuthStore((s) => s.setLocalIdentityReady);
  const setLocked = useAuthStore((s) => s.setLocked);
  const setNativeError = useAuthStore((s) => s.setNativeError);
  const nativeError = useAuthStore((s) => s.nativeError);

  useEffect(() => {
    let active = true;
    void VeilCrypto.hasIdentity()
      .then(async (hasIdentity) => {
        if (!active) return;
        if (!hasIdentity) {
          setLocked();
          return;
        }
        const publicIdentityKey = await VeilCrypto.getIdentityKey();
        if (active) setLocalIdentityReady(publicIdentityKey);
      })
      .catch((error) => {
        if (active) setNativeError(error instanceof Error ? error.message : "Native identity runtime failed");
      });
    return () => {
      active = false;
    };
  }, [setLocalIdentityReady, setLocked, setNativeError]);

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
            {nativeIdentityState === "checking" ? (
              <Stack.Screen name="IdentityBootstrap" component={IdentityBootstrap} />
            ) : nativeIdentityState === "native_error" ? (
              <Stack.Screen name="NativeIdentityError">
                {() => <NativeIdentityError message={nativeError} />}
              </Stack.Screen>
            ) : nativeIdentityState === "locked" ? (
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

function IdentityBootstrap() {
  return (
    <View style={{ flex: 1, alignItems: "center", justifyContent: "center", backgroundColor: "#111117" }}>
      <ActivityIndicator color="#7c6bf5" />
    </View>
  );
}

function NativeIdentityError({ message }: { message: string | null }) {
  return (
    <View style={{ flex: 1, padding: 32, alignItems: "center", justifyContent: "center", backgroundColor: "#111117" }}>
      <Text style={{ color: "#ff6b78", fontSize: 17, fontWeight: "700", textAlign: "center" }}>
        Secure identity runtime unavailable
      </Text>
      <Text style={{ color: "#a7a7b0", fontSize: 13, lineHeight: 19, textAlign: "center", marginTop: 10 }}>
        {message ?? "Veil cannot safely open the local identity vault on this device."}
      </Text>
    </View>
  );
}
