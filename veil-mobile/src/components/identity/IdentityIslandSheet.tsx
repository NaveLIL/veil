import React, { useEffect, useRef } from "react";
import { Animated, BackHandler, Modal, Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import type { Member } from "../../stores/chat";
import { colors, radii, spacing } from "../../lib/theme";
import { UserAvatar } from "./UserAvatar";

interface Props {
  profile: Member | null;
  contextLabel: string;
  onClose: () => void;
  onMessage?: (profile: Member) => void;
}

export const IdentityIslandSheet: React.FC<Props> = ({ profile, contextLabel, onClose, onMessage }) => {
  const progress = useRef(new Animated.Value(0)).current;
  const insets = useSafeAreaInsets();
  useEffect(() => {
    if (!profile) return;
    progress.setValue(0);
    Animated.spring(progress, { toValue: 1, damping: 22, stiffness: 230, mass: 0.9, useNativeDriver: true }).start();
    const subscription = BackHandler.addEventListener("hardwareBackPress", () => { onClose(); return true; });
    return () => subscription.remove();
  }, [profile, progress, onClose]);
  if (!profile) return null;
  const shortKey = `${profile.identityKey.slice(0, 12)}…${profile.identityKey.slice(-8)}`;
  return (
    <Modal visible transparent animationType="none" onRequestClose={onClose} statusBarTranslucent>
      <View style={styles.modal} accessibilityViewIsModal>
        <Pressable accessibilityLabel="Close identity" style={StyleSheet.absoluteFill} onPress={onClose}>
          <Animated.View style={[StyleSheet.absoluteFill, styles.scrim, { opacity: progress }]} />
        </Pressable>
        <Animated.View style={[styles.sheet, { paddingBottom: Math.max(insets.bottom, spacing.md), transform: [{ translateY: progress.interpolate({ inputRange: [0, 1], outputRange: [560, 0] }) }] }]}>
          <View style={styles.handle} />
          <View style={styles.header}>
            <Pressable accessibilityRole="button" onPress={onClose} hitSlop={12}><Text style={styles.back}>‹ Members</Text></Pressable>
            <Text style={styles.headerTitle}>Identity</Text>
            <Pressable accessibilityRole="button" accessibilityLabel="Close" onPress={onClose} hitSlop={12}><Text style={styles.close}>×</Text></Pressable>
          </View>
          <ScrollView contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
            <View style={styles.section}>
              <Text style={styles.sectionTitle}>Person</Text>
              <View style={styles.person}>
                <UserAvatar identityKey={profile.identityKey} userId={profile.userId} username={profile.username} size={82} />
                <Text style={styles.name}>{profile.name}</Text>
                {profile.name !== profile.username ? <Text style={styles.username}>@{profile.username}</Text> : null}
                {profile.about ? <Text style={styles.about}>{profile.about}</Text> : null}
              </View>
            </View>
            <View style={styles.section}>
              <Text style={styles.sectionTitle}>Context</Text>
              <Detail label="Seen as" value={contextLabel} />
              <Detail label="Presence" value={profile.status} />
              {profile.role ? <View style={styles.role}><Text style={styles.roleText}>{profile.role}</Text></View> : null}
              <Text style={styles.note}>Nicknames, roles and presence are context only. They never affect trust, access or encryption keys.</Text>
            </View>
            <View style={styles.section}>
              <Text style={styles.sectionTitle}>Identity Proof</Text>
              <Text style={styles.proofTitle}>Not compared</Text>
              <Text style={styles.note}>This identity was observed through the authenticated server (service-mediated TOFU). It is not verified on this device.</Text>
              <Detail label="Server origin" value={profile.canonicalServerOrigin} mono />
              <Detail label="Account ID" value={profile.userId} mono />
              <Detail label="Observed identity key" value={shortKey} mono />
            </View>
            {onMessage ? <Pressable style={styles.message} accessibilityRole="button" onPress={() => onMessage(profile)}><Text style={styles.messageText}>Message</Text></Pressable> : null}
          </ScrollView>
        </Animated.View>
      </View>
    </Modal>
  );
};

const Detail = ({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) => <View style={styles.detail}><Text style={styles.detailLabel}>{label}</Text><Text selectable={mono} style={[styles.detailValue, mono && styles.mono]}>{value}</Text></View>;

const styles = StyleSheet.create({
  modal: { flex: 1, justifyContent: "flex-end" }, scrim: { backgroundColor: "rgba(4,7,12,0.72)" },
  sheet: { maxHeight: "88%", backgroundColor: "#192735", borderTopLeftRadius: 26, borderTopRightRadius: 26, borderWidth: StyleSheet.hairlineWidth, borderColor: "rgba(124,107,245,0.3)", overflow: "hidden" },
  handle: { width: 42, height: 4, borderRadius: 2, backgroundColor: colors.textXLo, alignSelf: "center", marginTop: 8 },
  header: { height: 52, paddingHorizontal: spacing.lg, flexDirection: "row", alignItems: "center", justifyContent: "space-between", borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: colors.border },
  back: { color: colors.primaryHi, fontSize: 13 }, headerTitle: { color: colors.textHi, fontWeight: "800", letterSpacing: 1.4, textTransform: "uppercase", fontSize: 12 }, close: { color: colors.textMd, fontSize: 24 },
  content: { padding: spacing.md, gap: spacing.md }, section: { padding: spacing.md, borderRadius: radii.lg, borderWidth: StyleSheet.hairlineWidth, borderColor: colors.border, backgroundColor: "rgba(255,255,255,0.025)" },
  sectionTitle: { color: colors.textLo, fontSize: 10, fontWeight: "800", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: spacing.md }, person: { alignItems: "center" }, name: { color: colors.textHi, fontSize: 18, fontWeight: "800", marginTop: 10 }, username: { color: colors.textLo, fontSize: 12, marginTop: 2 }, about: { color: colors.textMd, fontSize: 13, lineHeight: 19, textAlign: "center", marginTop: 10 },
  detail: { marginTop: 8 }, detailLabel: { color: colors.textLo, fontSize: 10 }, detailValue: { color: colors.textHi, fontSize: 12, marginTop: 3 }, mono: { fontFamily: "monospace", fontSize: 11 },
  role: { alignSelf: "flex-start", marginTop: 12, paddingHorizontal: 9, paddingVertical: 4, borderRadius: radii.pill, borderWidth: 1, borderColor: colors.warningBorder, backgroundColor: colors.warningBg }, roleText: { color: colors.warning, fontSize: 10, textTransform: "uppercase", fontWeight: "800" },
  proofTitle: { color: colors.warning, fontSize: 14, fontWeight: "800" }, note: { color: colors.textLo, fontSize: 11, lineHeight: 17, marginTop: 8 },
  message: { height: 46, borderRadius: radii.lg, backgroundColor: colors.primary, alignItems: "center", justifyContent: "center" }, messageText: { color: "white", fontSize: 14, fontWeight: "800" },
});
