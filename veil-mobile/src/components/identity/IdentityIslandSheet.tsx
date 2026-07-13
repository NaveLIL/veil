import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AccessibilityInfo, Animated, BackHandler, findNodeHandle, Modal, Pressable, ScrollView, StyleSheet, Text, useWindowDimensions, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import type { Member } from "../../stores/chat";
import { colors, radii, spacing } from "../../lib/theme";
import { UserAvatar } from "./UserAvatar";
import { authoritativeIdentityLocator } from "./IdentityProof";

interface Props {
  profile: Member | null;
  contextLabel: string;
  returnLabel?: string;
  onClose: () => void;
  onMessage?: (profile: Member) => void;
}

export const IdentityIslandSheet: React.FC<Props> = ({ profile, contextLabel, returnLabel = "Members", onClose, onMessage }) => {
  const progress = useRef(new Animated.Value(0)).current;
  const closeButtonRef = useRef<View>(null);
  const reduceMotionRef = useRef(true);
  const motionPreferenceResolvedRef = useRef(false);
  const closingRef = useRef(false);
  const closeDeliveredRef = useRef(false);
  const mountedRef = useRef(true);
  const profileRef = useRef(profile);
  profileRef.current = profile;
  const insets = useSafeAreaInsets();
  const { height: windowHeight } = useWindowDimensions();
  const [motionPreferenceResolved, setMotionPreferenceResolved] = useState(false);

  const startEntryAnimation = useCallback(() => {
    progress.setValue(0);
    Animated.spring(progress, {
      toValue: 1,
      damping: 22,
      stiffness: 230,
      mass: 0.9,
      useNativeDriver: true,
    }).start();
  }, [progress]);

  const finishClose = useCallback(() => {
    if (!mountedRef.current || !closingRef.current || closeDeliveredRef.current) return;
    closingRef.current = false;
    closeDeliveredRef.current = true;
    onClose();
  }, [onClose]);

  useEffect(() => () => {
    mountedRef.current = false;
    closingRef.current = false;
    progress.stopAnimation();
  }, [progress]);

  useEffect(() => {
    let mounted = true;
    void AccessibilityInfo.isReduceMotionEnabled().then((enabled) => {
      if (!mounted || motionPreferenceResolvedRef.current) return;
      reduceMotionRef.current = enabled;
      motionPreferenceResolvedRef.current = true;
      setMotionPreferenceResolved(true);
    }).catch(() => {
      // Fail safe: keep motion disabled when the platform capability cannot be read.
      if (!mounted || motionPreferenceResolvedRef.current) return;
      reduceMotionRef.current = true;
      motionPreferenceResolvedRef.current = true;
      setMotionPreferenceResolved(true);
    });
    const subscription = AccessibilityInfo.addEventListener("reduceMotionChanged", (enabled) => {
      const firstResolution = !motionPreferenceResolvedRef.current;
      reduceMotionRef.current = enabled;
      motionPreferenceResolvedRef.current = true;
      if (firstResolution) {
        setMotionPreferenceResolved(true);
        return;
      }
      if (enabled) {
        progress.stopAnimation();
        if (closingRef.current) finishClose();
        else if (profileRef.current) progress.setValue(1);
      }
    });
    return () => {
      mounted = false;
      subscription.remove();
    };
  }, [finishClose, progress]);

  const requestClose = useCallback(() => {
    if (closingRef.current || closeDeliveredRef.current) return;
    closingRef.current = true;
    progress.stopAnimation();
    if (reduceMotionRef.current) {
      finishClose();
      return;
    }
    Animated.timing(progress, { toValue: 0, duration: 170, useNativeDriver: true }).start(() => {
      // A platform interruption must not strand an inaccessible modal.
      finishClose();
    });
  }, [finishClose, progress]);

  useEffect(() => {
    if (!profile) {
      closeDeliveredRef.current = false;
      closingRef.current = false;
      progress.stopAnimation();
      progress.setValue(0);
      return;
    }
    if (!motionPreferenceResolved || closingRef.current || closeDeliveredRef.current) return;
    if (reduceMotionRef.current) progress.setValue(1);
    else startEntryAnimation();
  }, [motionPreferenceResolved, profile, progress, startEntryAnimation]);

  useEffect(() => {
    if (!profile) return;
    const subscription = BackHandler.addEventListener("hardwareBackPress", () => { requestClose(); return true; });
    return () => subscription.remove();
  }, [profile, requestClose]);

  const locator = useMemo(() => {
    if (!profile) return null;
    return authoritativeIdentityLocator(profile);
  }, [profile]);

  if (!profile || !motionPreferenceResolved) return null;
  const shortKey = locator ? `${locator.identityKey.slice(0, 12)}…${locator.identityKey.slice(-8)}` : null;
  return (
    <Modal
      visible
      transparent
      animationType="none"
      onRequestClose={requestClose}
      onShow={() => {
        const handle = findNodeHandle(closeButtonRef.current);
        if (handle) AccessibilityInfo.setAccessibilityFocus(handle);
      }}
      statusBarTranslucent
    >
      <View style={styles.modal} accessibilityViewIsModal>
        <Pressable accessibilityRole="button" accessibilityLabel="Close identity" style={StyleSheet.absoluteFill} onPress={requestClose}>
          <Animated.View style={[StyleSheet.absoluteFill, styles.scrim, { opacity: progress }]} />
        </Pressable>
        <Animated.View style={[styles.sheet, { paddingBottom: Math.max(insets.bottom, spacing.md), transform: [{ translateY: progress.interpolate({ inputRange: [0, 1], outputRange: [Math.max(windowHeight, 1), 0] }) }] }]}>
          <View style={styles.handle} />
          <View style={styles.header}>
            <Pressable accessibilityRole="button" onPress={requestClose} hitSlop={12}><Text style={styles.back}>‹ {returnLabel}</Text></Pressable>
            <Text accessibilityRole="header" style={styles.headerTitle}>Identity</Text>
            <Pressable ref={closeButtonRef} focusable accessibilityRole="button" accessibilityLabel="Close" onPress={requestClose} hitSlop={12}><Text style={styles.close}>×</Text></Pressable>
          </View>
          <ScrollView contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
            <View style={styles.section}>
              <Text accessibilityRole="header" style={styles.sectionTitle}>Person</Text>
              <View style={styles.person}>
                <UserAvatar identityKey={profile.identityKey} canonicalServerOrigin={profile.canonicalServerOrigin} userId={profile.userId} technicalUsername={profile.username} size={82} label={`${profile.name} Phaseprint`} />
                <Text style={styles.name}>{profile.name}</Text>
                {profile.name !== profile.username ? <Text style={styles.username}>@{profile.username}</Text> : null}
                {profile.about ? <Text style={styles.about}>{profile.about}</Text> : null}
                <Text style={styles.profilePrivacy}>Profile name, about and profile image are visible to this Veil server. They are not end-to-end encrypted.</Text>
              </View>
            </View>
            <View style={styles.section}>
              <Text accessibilityRole="header" style={styles.sectionTitle}>Context</Text>
              <Detail label="Seen as" value={contextLabel} />
              <Detail label="Presence" value={profile.status} />
              {profile.role ? <View style={styles.role}><Text style={styles.roleText}>{profile.role}</Text></View> : null}
              <Text style={styles.note}>Nicknames, roles and presence are context only. They never affect trust, access or encryption keys.</Text>
            </View>
            <View style={styles.section}>
              <Text accessibilityRole="header" style={styles.sectionTitle}>Identity Proof</Text>
              {locator ? (
                <>
                  <Text style={styles.proofTitle}>Not compared</Text>
                  <Text style={styles.note}>This exact origin-scoped identity was observed through the authenticated server (service-mediated TOFU). It is not verified on this device.</Text>
                  <Detail label="Server origin" value={locator.canonicalServerOrigin} mono />
                  <Detail label="Account ID" value={locator.userId} mono />
                  <Detail label="Observed identity key" value={shortKey!} mono />
                </>
              ) : (
                <>
                  <Text style={styles.proofUnavailable}>Identity unavailable</Text>
                  <Text style={styles.note}>Veil has no authenticated origin, account and identity-key locator for this entry. No trust claim is shown.</Text>
                </>
              )}
            </View>
            {onMessage && locator ? <Pressable style={styles.message} accessibilityRole="button" onPress={() => onMessage(profile)}><Text style={styles.messageText}>Message</Text></Pressable> : null}
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
  profilePrivacy: { color: colors.textLo, fontSize: 10, lineHeight: 15, textAlign: "center", marginTop: 10 },
  detail: { marginTop: 8 }, detailLabel: { color: colors.textLo, fontSize: 10 }, detailValue: { color: colors.textHi, fontSize: 12, marginTop: 3 }, mono: { fontFamily: "monospace", fontSize: 11 },
  role: { alignSelf: "flex-start", marginTop: 12, paddingHorizontal: 9, paddingVertical: 4, borderRadius: radii.pill, borderWidth: 1, borderColor: colors.warningBorder, backgroundColor: colors.warningBg }, roleText: { color: colors.warning, fontSize: 10, textTransform: "uppercase", fontWeight: "800" },
  proofTitle: { color: colors.warning, fontSize: 14, fontWeight: "800" }, proofUnavailable: { color: "#f87171", fontSize: 14, fontWeight: "800" }, note: { color: colors.textLo, fontSize: 11, lineHeight: 17, marginTop: 8 },
  message: { height: 46, borderRadius: radii.lg, backgroundColor: colors.primary, alignItems: "center", justifyContent: "center" }, messageText: { color: "white", fontSize: 14, fontWeight: "800" },
});
