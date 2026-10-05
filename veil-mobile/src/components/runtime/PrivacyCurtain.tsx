import { runtimeCopy } from '../../presentation/copy/runtime';
import React from "react";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import { spacing } from "../../lib/theme";
import { geometry, type Palette } from "../../interfacePreview/appearance";
import { usePresentation } from "../../interfacePreview/PresentationContext";
import { useVeilStyles } from "../../interfacePreview/useVeilStyles";

export function PrivacyCurtain({ reducedMotion = false }: { reducedMotion?: boolean }) {
  const { c } = usePresentation();
  const styles = useVeilStyles(createStyles);
  return (
    <View
      testID="privacy-curtain"
      accessibilityViewIsModal
      accessibilityRole="progressbar"
      accessibilityLabel={runtimeCopy("Veil is securing and locking the local account")}
      accessibilityLiveRegion="assertive"
      style={styles.overlay}
    >
      <SafeAreaView style={styles.safe}>
        <View style={styles.mark} importantForAccessibility="no">
          <Text style={styles.markText}>V</Text>
        </View>
        <Text style={styles.title}>{runtimeCopy("Veil is locked")}</Text>
        <Text style={styles.body}>{runtimeCopy("Securing the local session before this screen can be shown again.")}</Text>
        {reducedMotion ? null : (
          <ActivityIndicator
            accessibilityElementsHidden
            importantForAccessibility="no-hide-descendants"
            color={c.accent}
            style={styles.progress}
          />
        )}
      </SafeAreaView>
    </View>
  );
}

const createStyles = (c: Palette) => StyleSheet.create({
  overlay: {
    ...StyleSheet.absoluteFillObject,
    zIndex: 10_000,
    elevation: 10_000,
    backgroundColor: c.bg,
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
    borderRadius: geometry.radius,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: c.tint,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.line,
    marginBottom: spacing.xl,
  },
  markText: {
    color: c.accent,
    fontWeight: "800",
    fontSize: 24,
  },
  title: {
    color: c.text,
    fontSize: 22,
    fontWeight: "800",
    textAlign: "center",
  },
  body: {
    color: c.text,
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
