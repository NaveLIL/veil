import React from "react";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import { colors, radii, spacing } from "../../lib/theme";

export function PrivacyCurtain({ reducedMotion = false }: { reducedMotion?: boolean }) {
  return (
    <View
      testID="privacy-curtain"
      accessibilityViewIsModal
      accessibilityRole="progressbar"
      accessibilityLabel="Veil is securing and locking the local account"
      accessibilityLiveRegion="assertive"
      style={styles.overlay}
    >
      <SafeAreaView style={styles.safe}>
        <View style={styles.mark} importantForAccessibility="no">
          <Text style={styles.markText}>V</Text>
        </View>
        <Text style={styles.title}>Veil is locked</Text>
        <Text style={styles.body}>
          Securing the local session before this screen can be shown again.
        </Text>
        {reducedMotion ? null : (
          <ActivityIndicator
            accessibilityElementsHidden
            importantForAccessibility="no-hide-descendants"
            color={colors.primaryHi}
            style={styles.progress}
          />
        )}
      </SafeAreaView>
    </View>
  );
}

const styles = StyleSheet.create({
  overlay: {
    ...StyleSheet.absoluteFillObject,
    zIndex: 10_000,
    elevation: 10_000,
    backgroundColor: "#09090d",
  },
  safe: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    padding: spacing.xxl,
  },
  mark: {
    width: 64,
    height: 64,
    borderRadius: radii.xl,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "#24203d",
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: "rgba(155,138,251,0.5)",
    marginBottom: spacing.xl,
  },
  markText: {
    color: colors.primaryHi,
    fontWeight: "800",
    fontSize: 24,
  },
  title: {
    color: colors.textHi,
    fontSize: 22,
    fontWeight: "800",
    textAlign: "center",
  },
  body: {
    color: colors.textMd,
    fontSize: 15,
    lineHeight: 22,
    textAlign: "center",
    maxWidth: 360,
    marginTop: spacing.sm,
  },
  progress: {
    marginTop: spacing.xl,
  },
});
