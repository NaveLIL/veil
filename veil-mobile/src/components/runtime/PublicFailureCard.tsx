import React from "react";
import { StyleSheet, Text, View } from "react-native";

import {
  type PublicFailureCodeV1,
} from "../../contracts/publicFailureCodesV1";
import { geometry, typography } from '../../interfacePreview/appearance';
import { usePresentation } from '../../interfacePreview/PresentationContext';
import { publicFailureCopy } from '../../presentation/copy/publicFailures';

export function PublicFailureCard({
  code,
  compact = false,
  announce = true,
}: {
  code: PublicFailureCodeV1;
  compact?: boolean;
  announce?: boolean;
}) {
  const failure = publicFailureCopy(code);
  const { c } = usePresentation();
  return (
    <View
      testID="public-failure-card-v1"
      accessibilityRole={announce ? "alert" : undefined}
      accessibilityLiveRegion={announce ? "assertive" : "none"}
      style={[styles.card, compact && styles.compact, {borderRadius:geometry.radius, borderColor:c.danger, backgroundColor:c.surface}]}
    >
      <Text accessibilityRole="header" style={[styles.title, {color:c.text}]}>{failure.title}</Text>
      <Text style={[styles.description, {color:c.muted}]}>{failure.description}</Text>
      <Text style={[styles.actionLabel, {color:c.muted}]}>Что делать</Text>
      <Text style={[styles.action, {color:c.text}]}>{failure.nextAction}</Text>
      <Text
        testID="public-failure-code-v1"
        accessibilityLabel={`Публичный код ошибки ${failure.code}`}
        selectable
        style={[styles.code, {color:c.danger}]}
      >
        {failure.code}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    borderRadius: geometry.radius,
    borderWidth: StyleSheet.hairlineWidth,
    padding: 12,
  },
  compact: { marginTop: 12 },
  title: { ...typography.body, fontWeight: '600' },
  description: { ...typography.caption, marginTop: 5 },
  actionLabel: {
    ...typography.caption,
    fontWeight: "900",
    letterSpacing: 1.2,
    marginTop: 12,
  },
  action: { ...typography.caption, marginTop: 3 },
  code: {
    alignSelf: "flex-start",
    fontFamily: "monospace",
    fontSize: 12,
    fontWeight: "800",
    letterSpacing: 0.5,
    marginTop: 12,
  },
});
