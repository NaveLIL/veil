import React from "react";
import { StyleSheet, Text, View } from "react-native";

import {
  publicFailurePresentationV1,
  type PublicFailureCodeV1,
} from "../../contracts/publicFailureCodesV1";
import { colors, radii, spacing } from "../../lib/theme";

export function PublicFailureCard({
  code,
  compact = false,
  announce = true,
}: {
  code: PublicFailureCodeV1;
  compact?: boolean;
  announce?: boolean;
}) {
  const failure = publicFailurePresentationV1(code);
  return (
    <View
      testID="public-failure-card-v1"
      accessibilityRole={announce ? "alert" : undefined}
      accessibilityLiveRegion={announce ? "assertive" : "none"}
      style={[styles.card, compact && styles.compact]}
    >
      <Text accessibilityRole="header" style={styles.title}>{failure.title}</Text>
      <Text style={styles.description}>{failure.description}</Text>
      <Text style={styles.actionLabel}>NEXT ACTION</Text>
      <Text style={styles.action}>{failure.nextAction}</Text>
      <Text
        testID="public-failure-code-v1"
        accessibilityLabel={`Public failure code ${failure.code}`}
        selectable
        style={styles.code}
      >
        {failure.code}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    borderRadius: radii.lg,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.destructiveBorder,
    backgroundColor: colors.destructiveBg,
    padding: spacing.md,
  },
  compact: { marginTop: spacing.md },
  title: { color: colors.textHi, fontSize: 15, fontWeight: "800" },
  description: { color: colors.textMd, fontSize: 13, lineHeight: 19, marginTop: 5 },
  actionLabel: {
    color: colors.textLo,
    fontSize: 9,
    fontWeight: "900",
    letterSpacing: 1.2,
    marginTop: spacing.md,
  },
  action: { color: colors.textHi, fontSize: 13, lineHeight: 19, marginTop: 3 },
  code: {
    alignSelf: "flex-start",
    color: colors.destructive,
    fontFamily: "monospace",
    fontSize: 12,
    fontWeight: "800",
    letterSpacing: 0.5,
    marginTop: spacing.md,
  },
});
