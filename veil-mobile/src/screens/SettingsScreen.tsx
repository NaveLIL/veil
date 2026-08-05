import React from "react";
import {
  Linking,
  Pressable,
  ScrollView,
  StyleSheet,
  Switch,
  Text,
  View,
} from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import {
  Bell,
  ChevronRight,
  Database,
  Info,
  KeyRound,
  Palette,
  Server,
  ShieldCheck,
  Smartphone,
  type LucideIcon,
} from "lucide-react-native";

import appConfig from "../../app.json";
import { MobileHeader } from "../components/navigation/MobileHeader";
import { Island } from "../components/ui/Island";
import { colors, radii, spacing } from "../lib/theme";
import { useRuntimeGateStore } from "../stores/runtime";
import { useMobileSettingsStore } from "../stores/settings";
import type {
  AuthenticatedStackParamList,
  SettingsSectionKey,
} from "./ChatListScreen";

type RootProps = NativeStackScreenProps<AuthenticatedStackParamList, "Settings">;
type DetailProps = NativeStackScreenProps<AuthenticatedStackParamList, "SettingsDetail">;
type Tone = "normal" | "positive" | "warning" | "muted";

const BUILD_CHANNEL = __DEV__ ? "Development build" : "Closed Direct Preview";

const SETTINGS_SECTIONS: {
  key: SettingsSectionKey;
  icon: LucideIcon;
  title: string;
  summary: string;
}[] = [
  { key: "account", icon: KeyRound, title: "Account & recovery", summary: "Local identity and recovery boundaries" },
  { key: "devices", icon: Smartphone, title: "Devices", summary: "This phone, linking and revocation" },
  { key: "privacy", icon: ShieldCheck, title: "Privacy & security", summary: "Lock, capture and identity trust" },
  { key: "notifications", icon: Bell, title: "Notifications", summary: "Push privacy, mentions and replies" },
  { key: "appearance", icon: Palette, title: "Appearance", summary: "Theme, motion and readable content" },
  { key: "node", icon: Server, title: "Node & connection", summary: "Origin, transport and connection state" },
  { key: "storage", icon: Database, title: "Data & storage", summary: "Encrypted local data and future media" },
  { key: "about", icon: Info, title: "About & diagnostics", summary: "Build, safety status and support" },
];

export default function SettingsScreen({ navigation }: RootProps) {
  const insets = useSafeAreaInsets();
  return (
    <View testID="settings-screen" style={styles.root}>
      <MobileHeader
        title="Settings"
        subtitle="Veil on this device"
        backAction={{ label: "Home", onPress: () => navigation.goBack() }}
      />
      <ScrollView
        testID="settings-root-scroll"
        contentContainerStyle={[
          styles.rootContent,
          {
            paddingBottom: insets.bottom + spacing.md,
            paddingLeft: Math.max(spacing.md, insets.left),
            paddingRight: Math.max(spacing.md, insets.right),
          },
        ]}
        showsVerticalScrollIndicator={false}
      >
        <Island variant="solid" glow={false} padding={0}>
          {SETTINGS_SECTIONS.map((section, index) => (
            <SettingsSectionRow
              key={section.key}
              section={section}
              divided={index > 0}
              onPress={() => navigation.navigate("SettingsDetail", { section: section.key })}
            />
          ))}
        </Island>
        <Text style={styles.footer}>
          Only controls backed by the current native runtime are interactive. Planned settings remain clearly labelled.
        </Text>
      </ScrollView>
    </View>
  );
}

function SettingsSectionRow({
  section,
  divided,
  onPress,
}: {
  section: typeof SETTINGS_SECTIONS[number];
  divided: boolean;
  onPress: () => void;
}) {
  const Icon = section.icon;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`${section.title}. ${section.summary}`}
      onPress={onPress}
      style={({ pressed }) => [
        styles.sectionRow,
        divided && styles.rowDivider,
        pressed && styles.pressed,
      ]}
    >
      <View style={styles.sectionMark}>
        <Icon size={19} strokeWidth={1.9} color={colors.primaryHi} />
      </View>
      <View style={styles.sectionMeta}>
        <Text style={styles.sectionName}>{section.title}</Text>
        <Text numberOfLines={2} style={styles.sectionSummary}>{section.summary}</Text>
      </View>
      <ChevronRight
        importantForAccessibility="no"
        size={21}
        strokeWidth={1.8}
        color={colors.textLo}
      />
    </Pressable>
  );
}

export function SettingsDetailScreen({ navigation, route }: DetailProps) {
  const insets = useSafeAreaInsets();
  const snapshot = useRuntimeGateStore((state) => state.snapshot);
  const allowReadyScreenshots = useMobileSettingsStore(
    (state) => state.allowReadyScreenshots,
  );
  const setAllowReadyScreenshots = useMobileSettingsStore(
    (state) => state.setAllowReadyScreenshots,
  );
  const definition = settingsDefinition(route.params.section, snapshot, {
    allowReadyScreenshots,
    setAllowReadyScreenshots,
    openAndroidSettings: () => {
      void Linking.openSettings().catch(() => undefined);
    },
    openProjectWebsite: () => {
      void Linking.openURL("https://veil.erez.pro").catch(() => undefined);
    },
  });

  return (
    <View testID={`settings-${route.params.section}`} style={styles.root}>
      <MobileHeader
        title={definition.title}
        subtitle={definition.subtitle}
        backAction={{ label: "Settings", onPress: () => navigation.goBack() }}
      />
      <ScrollView
        testID="settings-detail-scroll"
        contentContainerStyle={[
          styles.detailContent,
          {
            paddingBottom: insets.bottom + spacing.md,
            paddingLeft: Math.max(spacing.md, insets.left),
            paddingRight: Math.max(spacing.md, insets.right),
          },
        ]}
        showsVerticalScrollIndicator={false}
      >
        {definition.groups.map((group) => (
          <Island key={group.title} variant="solid" glow={false} padding={spacing.md}>
            <Text accessibilityRole="header" style={styles.groupTitle}>{group.title}</Text>
            {group.rows.map((row, index) => (
              <DetailRow key={row.label} {...row} divided={index > 0} />
            ))}
            {group.note ? <Text style={styles.note}>{group.note}</Text> : null}
          </Island>
        ))}
      </ScrollView>
    </View>
  );
}

interface DetailDefinition {
  title: string;
  subtitle: string;
  groups: {
    title: string;
    rows: DetailRowProps[];
    note?: string;
  }[];
}

interface DetailRowProps {
  label: string;
  value?: string;
  detail?: string;
  tone?: Tone;
  mono?: boolean;
  selectable?: boolean;
  onPress?: () => void;
  switchValue?: boolean;
  onSwitchChange?: (value: boolean) => void;
  switchDisabled?: boolean;
}

interface SettingsActions {
  allowReadyScreenshots: boolean;
  setAllowReadyScreenshots: (allowed: boolean) => void;
  openAndroidSettings: () => void;
  openProjectWebsite: () => void;
}

function settingsDefinition(
  section: SettingsSectionKey,
  snapshot: ReturnType<typeof useRuntimeGateStore.getState>["snapshot"],
  actions: SettingsActions,
): DetailDefinition {
  const connected = snapshot?.connectionState === "connected";
  const origin = snapshot?.binding?.canonicalServerOrigin ?? "Unavailable";

  switch (section) {
    case "account":
      return {
        title: "Account & recovery",
        subtitle: "Identity stays native",
        groups: [
          {
            title: "Local account",
            rows: [
              { label: "Identity", value: snapshot?.identityExists ? "Available" : "Unavailable", tone: snapshot?.identityExists ? "positive" : "warning" },
              { label: "Session", value: snapshot?.sessionState === "open" ? "Open on this device" : "Locked", tone: snapshot?.sessionState === "open" ? "positive" : "muted" },
              { label: "Recovery setup", value: "Native protected", detail: "Recovery words never enter React Native.", tone: "positive" },
            ],
            note: "Viewing, replacing or exporting recovery material will always open a separate FLAG_SECURE native ceremony.",
          },
          {
            title: "Identity trust",
            rows: [
              { label: "Fingerprint comparison", value: "Assurance phase", detail: "Cross-client compare and QR belong to Phase 5S.", tone: "warning" },
              { label: "Key changes", value: "Fail closed", detail: "A changed peer identity must never be accepted silently.", tone: "positive" },
            ],
          },
        ],
      };
    case "devices":
      return {
        title: "Devices",
        subtitle: "One account, explicit devices",
        groups: [
          {
            title: "This device",
            rows: [
              { label: "Android phone", value: connected ? "Active" : "Local only", tone: connected ? "positive" : "muted" },
              { label: "Process restart", value: "Same-account restore", detail: "Physically verified without a new Access Pass.", tone: "positive" },
            ],
          },
          {
            title: "Device management",
            rows: [
              { label: "Link another device", value: "Secure QR · Phase 5C", detail: "Ephemeral challenge, matching code and explicit approval.", tone: "warning" },
              { label: "Review and revoke", value: "Not connected yet", tone: "muted" },
            ],
            note: "Veil will never copy the recovery phrase or root identity through a linking QR.",
          },
        ],
      };
    case "privacy":
      return {
        title: "Privacy & security",
        subtitle: "Capture and lock boundaries",
        groups: [
          {
            title: "Screen privacy",
            rows: [
              { label: "Recent apps preview", value: "Always hidden", tone: "positive" },
              {
                label: "Screen capture for testing",
                detail: __DEV__
                  ? "Current development session only. Allows screenshots, screen recording and casting of Ready content; recovery, enrollment, background and Recents stay protected."
                  : "Release opt-in remains disabled until its physical capture matrix is complete.",
                switchValue: __DEV__ && actions.allowReadyScreenshots,
                onSwitchChange: actions.setAllowReadyScreenshots,
                switchDisabled: !__DEV__,
              },
              { label: "Recovery and enrollment", value: "Always protected", tone: "positive" },
            ],
            note: "Veil restores screen protection before Android can capture the app in the background, on lock or during reconnect.",
          },
          {
            title: "App access",
            rows: [
              { label: "Background lock", value: "Immediate", tone: "positive" },
              { label: "PIN and biometrics", value: "Not available yet", tone: "warning" },
              { label: "Overlay protection", value: "Recovery and setup", tone: "positive" },
            ],
          },
        ],
      };
    case "notifications":
      return {
        title: "Notifications",
        subtitle: "Private by default",
        groups: [
          {
            title: "Delivery",
            rows: [
              { label: "Push transport", value: "Not connected yet", tone: "muted" },
              { label: "Foreground sync", value: connected ? "Connected" : "Unavailable", tone: connected ? "positive" : "muted" },
              { label: "Lock-screen content", value: "Push-phase contract · generic only", tone: "muted" },
              { label: "Android app settings", value: "Open", detail: "Review permissions, notifications, battery usage and other Android controls.", onPress: actions.openAndroidSettings },
            ],
            note: "Message text, person, Circle, Space and Room stay out of push until the complete K_push lifecycle is verified.",
          },
          {
            title: "Attention",
            rows: [
              { label: "Unread", value: "Design contract · dot", tone: "muted" },
              { label: "Mention or reply", value: "Design contract · @ count", tone: "muted" },
              { label: "Per-context controls", value: "Push phase", tone: "muted" },
            ],
          },
        ],
      };
    case "appearance":
      return {
        title: "Appearance",
        subtitle: "One Veil, adapted to mobile",
        groups: [
          {
            title: "Visual system",
            rows: [
              { label: "Theme", value: "Veil dark" },
              { label: "Content surfaces", value: "Crisp islands" },
              { label: "Ambient light", value: "Onboarding and focus only" },
            ],
          },
          {
            title: "Accessibility",
            rows: [
              { label: "Reduced motion", value: "Follows Android", tone: "positive" },
              { label: "Text size", value: "Follows Android" },
              { label: "High contrast", value: "QA gate pending", tone: "warning" },
            ],
            note: "Desktop and mobile share visual tokens and semantics; only their spatial layout differs.",
          },
        ],
      };
    case "node":
      return {
        title: "Node & connection",
        subtitle: "Account and trust boundary",
        groups: [
          {
            title: "Current Veil Node",
            rows: [
              { label: "Connection", value: connected ? "Connected" : "Unavailable", tone: connected ? "positive" : "warning" },
              { label: "Canonical origin", value: origin, mono: true, selectable: true },
              { label: "Secure sync", value: snapshot?.secureSyncState === "history_synchronized" ? "Ready" : "Not ready", tone: snapshot?.secureSyncState === "history_synchronized" ? "positive" : "warning" },
            ],
            note: "A Veil Node is not a Space. Changing origin can change the account and trust scope and must always be explicit.",
          },
          {
            title: "Connection controls",
            rows: [
              { label: "Reconnect", value: "Automatic for safe transport failures", tone: "positive" },
              { label: "Private CA enrollment", value: "NodeTrustPolicy phase", tone: "muted" },
              { label: "Forget Node / stay offline", value: "Not connected yet", tone: "muted" },
            ],
          },
        ],
      };
    case "storage":
      return {
        title: "Data & storage",
        subtitle: "Encrypted on this device",
        groups: [
          {
            title: "Local data",
            rows: [
              { label: "Database", value: "SQLCipher", tone: "positive" },
              { label: "Android backup", value: "Disabled", tone: "positive" },
              { label: "Renderable plaintext", value: "Cleared on lock", tone: "positive" },
            ],
          },
          {
            title: "Media and search",
            rows: [
              { label: "Attachment cache", value: "Attachment phase", tone: "muted" },
              { label: "Offline media limit", value: "Not available yet", tone: "muted" },
              { label: "Local search index", value: "Search phase", tone: "muted" },
            ],
            note: "Future cleanup controls must never delete ratchet or outbox state as if it were disposable cache.",
          },
        ],
      };
    case "about":
      return {
        title: "About & diagnostics",
        subtitle: "Preview status without secrets",
        groups: [
          {
            title: "Build",
            rows: [
              { label: "Version", value: appConfig.expo.version, mono: true },
              { label: "Channel", value: BUILD_CHANNEL },
              { label: "Independent crypto audit", value: "Not completed", tone: "warning" },
            ],
          },
          {
            title: "Support",
            rows: [
              {
                label: "Public error codes",
                value: "Registry v1 · Setup/runtime gate",
                detail: "Direct send/delivery and Desktop/Go consumer parity remain open.",
                tone: "warning",
              },
              { label: "Copy safe diagnostics", value: "Not connected yet", tone: "muted" },
              { label: "Project website", value: "Open", onPress: actions.openProjectWebsite },
              { label: "Licensing", value: "AGPL-3.0-or-later" },
            ],
            note: "Diagnostics must exclude recovery words, Passes, keys, plaintext, raw URLs and account/device/message identifiers.",
          },
        ],
      };
  }
}

function DetailRow({
  label,
  value,
  detail,
  tone = "normal",
  mono = false,
  selectable = false,
  onPress,
  switchValue,
  onSwitchChange,
  switchDisabled = false,
  divided = false,
}: DetailRowProps & { divided?: boolean }) {
  const content = (
    <>
      <View style={styles.detailMeta}>
        <Text style={styles.detailLabel}>{label}</Text>
        {detail ? <Text style={styles.detailHint}>{detail}</Text> : null}
      </View>
      {switchValue !== undefined && onSwitchChange ? (
        <Switch
          accessible={false}
          pointerEvents="none"
          disabled={switchDisabled}
          value={switchValue}
          onValueChange={onSwitchChange}
          trackColor={{ false: colors.surfaceLowHover, true: "rgba(124,107,245,0.52)" }}
          thumbColor={switchValue ? colors.primaryHi : colors.textMd}
        />
      ) : (
        <>
          {value ? (
            <Text
              selectable={selectable}
              style={[
                styles.detailValue,
                mono && styles.mono,
                tone === "positive" && styles.positive,
                tone === "warning" && styles.warning,
                tone === "muted" && styles.muted,
              ]}
            >
              {value}
            </Text>
          ) : null}
          {onPress ? (
            <ChevronRight size={19} strokeWidth={1.8} color={colors.textLo} />
          ) : null}
        </>
      )}
    </>
  );

  if (switchValue !== undefined && onSwitchChange) {
    return (
      <Pressable
        accessibilityRole="switch"
        accessibilityLabel={label}
        accessibilityHint={detail}
        accessibilityState={{ checked: switchValue, disabled: switchDisabled }}
        disabled={switchDisabled}
        onPress={() => onSwitchChange(!switchValue)}
        style={({ pressed }) => [
          styles.detailRow,
          divided && styles.rowDivider,
          pressed && !switchDisabled && styles.pressed,
        ]}
      >
        {content}
      </Pressable>
    );
  }

  if (onPress) {
    return (
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={label}
        accessibilityHint={detail}
        onPress={onPress}
        style={({ pressed }) => [
          styles.detailRow,
          divided && styles.rowDivider,
          pressed && styles.pressed,
        ]}
      >
        {content}
      </Pressable>
    );
  }

  return <View style={[styles.detailRow, divided && styles.rowDivider]}>{content}</View>;
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  rootContent: {
    paddingBottom: spacing.xxl,
  },
  detailContent: {
    paddingBottom: spacing.xxl,
    gap: spacing.md,
  },
  sectionRow: {
    minHeight: 66,
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
  },
  pressed: { opacity: 0.65, backgroundColor: colors.surfaceLow },
  rowDivider: { borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: colors.borderSoft },
  sectionMark: {
    width: 34,
    height: 34,
    alignItems: "center",
    justifyContent: "center",
    borderRadius: radii.md,
    backgroundColor: "rgba(124,107,245,0.10)",
  },
  sectionMeta: { flex: 1, minWidth: 0 },
  sectionName: { color: colors.textHi, fontSize: 14, fontWeight: "700" },
  sectionSummary: { color: colors.textLo, fontSize: 11, lineHeight: 16, marginTop: 2 },
  footer: {
    color: colors.textLo,
    fontSize: 10,
    lineHeight: 16,
    textAlign: "center",
    paddingHorizontal: spacing.lg,
    marginTop: spacing.md,
  },
  groupTitle: {
    color: colors.textLo,
    fontSize: 10,
    fontWeight: "800",
    letterSpacing: 1.4,
    textTransform: "uppercase",
    marginBottom: spacing.xs,
  },
  detailRow: {
    minHeight: 52,
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
    paddingVertical: spacing.sm,
  },
  detailMeta: { flex: 1, minWidth: 0 },
  detailLabel: { color: colors.textMd, fontSize: 13, fontWeight: "600" },
  detailHint: { color: colors.textLo, fontSize: 10, lineHeight: 15, marginTop: 3 },
  detailValue: {
    flexShrink: 1,
    maxWidth: "46%",
    color: colors.textHi,
    fontSize: 11,
    lineHeight: 16,
    fontWeight: "700",
    textAlign: "right",
  },
  mono: { fontFamily: "monospace", fontSize: 9 },
  positive: { color: colors.success },
  warning: { color: colors.warning },
  muted: { color: colors.textLo },
  note: { color: colors.textLo, fontSize: 10, lineHeight: 16, marginTop: spacing.sm },
});
