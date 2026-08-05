import React from "react";
import { StyleSheet, View } from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";
import { Settings2 } from "lucide-react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { ChannelsIsland } from "../components/layout/ChannelsIsland";
import { MobileHeader } from "../components/navigation/MobileHeader";
import { colors } from "../lib/theme";
import type { AuthenticatedStackParamList } from "./ChatListScreen";

type Props = NativeStackScreenProps<AuthenticatedStackParamList, "Home">;

/**
 * Production authenticated Home currently exposes only native-backed Direct.
 * Design-preview Spaces/Updates live outside this entry graph until their
 * native projections and security semantics exist.
 */
export default function HomeScreen({ navigation }: Props) {
  const insets = useSafeAreaInsets();

  return (
    <View testID="home-screen" style={styles.root}>
      <MobileHeader
        showBrand
        title="Home"
        subtitle="Direct Preview"
        action={{
          label: "Settings",
          accessibilityLabel: "Open Settings",
          icon: Settings2,
          onPress: () => navigation.navigate("Settings"),
        }}
      />
      <ChannelsIsland
        bottomInset={insets.bottom}
        leftInset={insets.left}
        rightInset={insets.right}
        onSelect={(conversationId) => navigation.navigate("Direct", { conversationId })}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
});
