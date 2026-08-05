import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AccessibilityInfo, Animated, AppState, BackHandler, findNodeHandle, Linking, Modal, Pressable, ScrollView, StyleSheet, Text, useWindowDimensions, View } from "react-native";
import { CameraView, useCameraPermissions, type BarcodeScanningResult } from "expo-camera";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { Check, ChevronLeft, ScanLine, X } from "lucide-react-native";
import QRCode from "react-native-qrcode-svg";
import type { Member } from "../../stores/chat";
import { colors, radii, spacing } from "../../lib/theme";
import VeilRuntime, { type DirectIdentityVerification } from "../../native/runtime";
import { UserAvatar } from "./UserAvatar";
import { authoritativeIdentityLocator } from "./IdentityProof";

interface Props {
  profile: Member | null;
  contextLabel: string;
  returnLabel?: string;
  directVerification?: {
    conversationId: string;
    directGeneration: number;
  };
  onClose: () => void;
  onMessage?: (profile: Member) => void;
}

export const IdentityIslandSheet: React.FC<Props> = ({ profile, contextLabel, returnLabel = "Members", directVerification, onClose, onMessage }) => {
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
  const [verification, setVerification] = useState<DirectIdentityVerification | null>(null);
  const [verificationLoading, setVerificationLoading] = useState(false);
  const [verificationFailed, setVerificationFailed] = useState(false);
  const [verificationConfirming, setVerificationConfirming] = useState(false);
  const [cameraPermission, requestCameraPermission] = useCameraPermissions();
  const [scannerOpen, setScannerOpen] = useState(false);
  const [scannerOpening, setScannerOpening] = useState(false);
  const [scannerBusy, setScannerBusy] = useState(false);
  const [scannerError, setScannerError] = useState<string | null>(null);
  const scannerConsumedRef = useRef(false);
  const verificationRequestRef = useRef(0);

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
    scannerConsumedRef.current = true;
    progress.stopAnimation();
  }, [progress]);

  const dismissScanner = useCallback(() => {
    scannerConsumedRef.current = true;
    setScannerOpen(false);
    setScannerOpening(false);
    setScannerBusy(false);
  }, []);

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
    if (scannerOpen) {
      dismissScanner();
      return;
    }
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
  }, [dismissScanner, finishClose, progress, scannerOpen]);

  useEffect(() => {
    if (!profile) {
      dismissScanner();
      setScannerError(null);
      closeDeliveredRef.current = false;
      closingRef.current = false;
      progress.stopAnimation();
      progress.setValue(0);
      return;
    }
    if (!motionPreferenceResolved || closingRef.current || closeDeliveredRef.current) return;
    if (reduceMotionRef.current) progress.setValue(1);
    else startEntryAnimation();
  }, [dismissScanner, motionPreferenceResolved, profile, progress, startEntryAnimation]);

  useEffect(() => {
    if (!profile) return;
    const subscription = BackHandler.addEventListener("hardwareBackPress", () => { requestClose(); return true; });
    return () => subscription.remove();
  }, [profile, requestClose]);

  useEffect(() => {
    if (!scannerOpen) return;
    const subscription = AppState.addEventListener("change", (state) => {
      if (state !== "active") dismissScanner();
    });
    return () => subscription.remove();
  }, [dismissScanner, scannerOpen]);

  const locator = useMemo(() => {
    if (!profile) return null;
    return authoritativeIdentityLocator(profile);
  }, [profile]);

  useEffect(() => {
    const request = verificationRequestRef.current + 1;
    verificationRequestRef.current = request;
    setVerification(null);
    setVerificationFailed(false);
    setVerificationConfirming(false);
    dismissScanner();
    setScannerError(null);
    if (!profile || !locator || !directVerification) {
      setVerificationLoading(false);
      return;
    }
    setVerificationLoading(true);
    void VeilRuntime.getDirectIdentityVerification(
      directVerification.conversationId,
      directVerification.directGeneration,
    ).then((result) => {
      if (!mountedRef.current || verificationRequestRef.current !== request) return;
      const exact = result
        && result.canonicalServerOrigin === locator.canonicalServerOrigin
        && result.peerUserId === locator.userId
        ? result
        : null;
      setVerification(exact);
      setVerificationFailed(exact === null);
      setVerificationLoading(false);
    }).catch(() => {
      if (!mountedRef.current || verificationRequestRef.current !== request) return;
      setVerification(null);
      setVerificationFailed(true);
      setVerificationLoading(false);
    });
  }, [directVerification, dismissScanner, locator, profile]);

  const confirmVerification = useCallback(() => {
    if (
      verificationConfirming
      || !directVerification
      || !locator
      || !verification
      || verification.state === "verified_on_this_device"
    ) return;
    const request = verificationRequestRef.current + 1;
    verificationRequestRef.current = request;
    const expectedFingerprintHex = verification.fingerprintHex;
    setVerificationConfirming(true);
    setVerificationFailed(false);
    void VeilRuntime.confirmDirectIdentityVerification(
      directVerification.conversationId,
      directVerification.directGeneration,
      expectedFingerprintHex,
    ).then((result) => {
      if (!mountedRef.current || verificationRequestRef.current !== request) return;
      const exact = result
        && result.canonicalServerOrigin === locator.canonicalServerOrigin
        && result.peerUserId === locator.userId
        && result.fingerprintHex === expectedFingerprintHex
        && result.state === "verified_on_this_device"
        ? result
        : null;
      setVerification(exact);
      setVerificationFailed(exact === null);
      setVerificationConfirming(false);
    }).catch(() => {
      if (!mountedRef.current || verificationRequestRef.current !== request) return;
      setVerificationFailed(true);
      setVerificationConfirming(false);
    });
  }, [directVerification, locator, verification, verificationConfirming]);

  const openScanner = useCallback(() => {
    if (
      scannerOpening
      || scannerBusy
      || !directVerification
      || !locator
      || !verification
      || verification.state === "verified_on_this_device"
    ) return;
    const request = verificationRequestRef.current;
    const openWithPermission = async () => {
      setScannerOpening(true);
      setScannerError(null);
      try {
        const permission = cameraPermission?.granted
          ? cameraPermission
          : await requestCameraPermission();
        if (!mountedRef.current || verificationRequestRef.current !== request) return;
        if (!permission.granted) {
          setScannerError(permission.canAskAgain
            ? "Camera permission is required to scan an identity QR code."
            : "Camera access is blocked. Enable it in system settings to scan an identity QR code.");
          return;
        }
        scannerConsumedRef.current = false;
        setScannerOpen(true);
      } catch {
        if (mountedRef.current && verificationRequestRef.current === request) {
          setScannerError("Camera permission could not be checked. You can still compare the safety number manually.");
        }
      } finally {
        if (mountedRef.current && verificationRequestRef.current === request) {
          setScannerOpening(false);
        }
      }
    };
    void openWithPermission();
  }, [cameraPermission, directVerification, locator, requestCameraPermission, scannerBusy, scannerOpening, verification]);

  const scanIdentityQr = useCallback((result: BarcodeScanningResult) => {
    if (
      result.type !== "qr"
      || scannerConsumedRef.current
      || !scannerOpen
      || scannerBusy
      || !directVerification
      || !locator
      || !verification
      || verification.state === "verified_on_this_device"
    ) return;
    scannerConsumedRef.current = true;
    setScannerBusy(true);
    setScannerOpen(false);
    setScannerError(null);
    const request = verificationRequestRef.current + 1;
    verificationRequestRef.current = request;
    const expectedFingerprintHex = verification.fingerprintHex;
    const expectedQrPayload = verification.qrPayload;
    void VeilRuntime.confirmDirectIdentityVerificationQr(
      directVerification.conversationId,
      directVerification.directGeneration,
      result.data,
    ).then((confirmed) => {
      if (!mountedRef.current || verificationRequestRef.current !== request) return;
      const exact = confirmed
        && confirmed.canonicalServerOrigin === locator.canonicalServerOrigin
        && confirmed.peerUserId === locator.userId
        && confirmed.fingerprintHex === expectedFingerprintHex
        && confirmed.qrPayload === expectedQrPayload
        && confirmed.state === "verified_on_this_device"
        ? confirmed
        : null;
      setVerification(exact ?? verification);
      setVerificationFailed(false);
      setScannerError(exact
        ? null
        : "This QR code does not match the current person, server and Direct session. No verification was recorded.");
      setScannerBusy(false);
    }).catch(() => {
      if (!mountedRef.current || verificationRequestRef.current !== request) return;
      setVerificationFailed(false);
      setScannerError("This QR code could not verify the current Direct identity. No verification was recorded.");
      setScannerBusy(false);
    });
  }, [directVerification, locator, scannerBusy, scannerOpen, verification]);

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
        <Animated.View
          testID="identity-sheet-surface"
          style={[styles.sheet, { paddingBottom: insets.bottom + spacing.md, transform: [{ translateY: progress.interpolate({ inputRange: [0, 1], outputRange: [Math.max(windowHeight, 1), 0] }) }] }]}
        >
          <View style={styles.handle} />
          <View
            testID="identity-sheet-header"
            style={[
              styles.header,
              {
                paddingLeft: Math.max(spacing.lg, insets.left),
                paddingRight: Math.max(spacing.lg, insets.right),
              },
            ]}
          >
            <Pressable
              accessibilityRole="button"
              accessibilityLabel={`Back to ${returnLabel}`}
              onPress={requestClose}
              hitSlop={8}
              style={styles.headerSide}
            >
              <ChevronLeft size={17} strokeWidth={2.2} color={colors.primaryHi} />
              <Text numberOfLines={1} style={styles.back}>{returnLabel}</Text>
            </Pressable>
            <Text accessibilityRole="header" style={styles.headerTitle}>Identity</Text>
            <Pressable
              ref={closeButtonRef}
              focusable
              accessibilityRole="button"
              accessibilityLabel="Close"
              onPress={requestClose}
              hitSlop={8}
              style={[styles.headerSide, styles.headerSideEnd]}
            >
              <X size={21} strokeWidth={2} color={colors.textMd} />
            </Pressable>
          </View>
          <ScrollView
            testID="identity-sheet-content"
            contentContainerStyle={[
              styles.content,
              {
                paddingLeft: Math.max(spacing.md, insets.left),
                paddingRight: Math.max(spacing.md, insets.right),
              },
            ]}
            showsVerticalScrollIndicator={false}
          >
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
                  {directVerification ? (
                    verificationLoading ? (
                      <>
                        <Text style={styles.proofTitle}>Loading safety number…</Text>
                        <Text style={styles.note}>Veil is checking this exact Direct route against native authenticated state.</Text>
                      </>
                    ) : verification ? (
                      <>
                        <Text style={[
                          styles.proofTitle,
                          verification.state === "verified_on_this_device" && styles.proofVerified,
                          verification.state === "identity_changed" && styles.proofUnavailable,
                        ]}>
                          {verification.state === "verified_on_this_device"
                            ? "Verified on this device"
                            : verification.state === "identity_changed"
                              ? "Identity changed"
                              : "Not compared"}
                        </Text>
                        <Text style={styles.note}>
                          {verification.state === "identity_changed"
                            ? "The account keys no longer match the identity previously trusted on this device. Do not continue until you verify the person through another trusted channel."
                            : verification.state === "verified_on_this_device"
                              ? "You explicitly compared this account-v2 safety number for the exact server and account on this device."
                              : "Compare this safety number with the person through another trusted channel. The server cannot make two different account key pairs produce the same number."}
                        </Text>
                        <Text selectable style={styles.fingerprintEmoji}>{verification.fingerprintEmoji}</Text>
                        <Detail label="Account-v2 safety number" value={verification.fingerprintHex.match(/.{1,4}/g)?.join(" ") ?? verification.fingerprintHex} mono />
                        <View
                          accessible
                          accessibilityLabel="Account-v2 verification QR code"
                          testID="identity-verification-qr-container"
                          style={styles.qrCard}
                        >
                          <QRCode
                            testID="identity-verification-qr"
                            value={verification.qrPayload}
                            size={184}
                            quietZone={12}
                            ecl="H"
                            color="#08111b"
                            backgroundColor="#ffffff"
                          />
                        </View>
                        <Text style={styles.note}>Show this QR code on one device and scan it from the other. Veil accepts only the exact current account-v2 identity.</Text>
                        {verification.state !== "verified_on_this_device" ? (
                          <>
                            <Pressable
                              testID="scan-identity-verification"
                              accessibilityRole="button"
                              accessibilityLabel="Scan identity QR code"
                              disabled={scannerOpening || scannerBusy || verificationConfirming}
                              onPress={openScanner}
                              style={[styles.verifyButton, (scannerOpening || scannerBusy || verificationConfirming) && styles.verifyButtonDisabled]}
                            >
                              <ScanLine size={17} strokeWidth={2.4} color="white" />
                              <Text style={styles.verifyButtonText}>
                                {scannerOpening ? "Opening camera…" : scannerBusy ? "Checking QR code…" : "Scan identity QR"}
                              </Text>
                            </Pressable>
                            <Pressable
                              testID="confirm-identity-verification"
                              accessibilityRole="button"
                              accessibilityLabel="I compared this safety number"
                              disabled={verificationConfirming || scannerOpening || scannerBusy}
                              onPress={confirmVerification}
                              style={[styles.compareButton, (verificationConfirming || scannerOpening || scannerBusy) && styles.verifyButtonDisabled]}
                            >
                              <Check size={16} strokeWidth={2.4} color={colors.primaryHi} />
                              <Text style={styles.compareButtonText}>
                                {verificationConfirming ? "Confirming…" : verification.state === "identity_changed" ? "I compared the new identity" : "I compared this number"}
                              </Text>
                            </Pressable>
                          </>
                        ) : null}
                        {scannerError ? (
                          <>
                            <Text accessibilityRole="alert" style={styles.scanError}>{scannerError}</Text>
                            {cameraPermission?.canAskAgain === false ? (
                              <Pressable
                                accessibilityRole="button"
                                accessibilityLabel="Open camera settings"
                                onPress={() => { void Linking.openSettings(); }}
                                style={styles.settingsButton}
                              >
                                <Text style={styles.settingsButtonText}>Open camera settings</Text>
                              </Pressable>
                            ) : null}
                          </>
                        ) : null}
                        {verificationFailed ? <Text accessibilityRole="alert" style={styles.proofUnavailable}>Confirmation was not recorded. Reopen this identity and compare again.</Text> : null}
                      </>
                    ) : (
                      <>
                        <Text style={styles.proofUnavailable}>Safety number unavailable</Text>
                        <Text accessibilityRole={verificationFailed ? "alert" : undefined} style={styles.note}>The exact native Direct route is not currently available. No verification claim is shown.</Text>
                      </>
                    )
                  ) : (
                    <>
                      <Text style={styles.proofTitle}>Not compared</Text>
                      <Text style={styles.note}>This exact origin-scoped identity was observed through the authenticated server (service-mediated TOFU). It is not verified on this device.</Text>
                    </>
                  )}
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
        {scannerOpen && cameraPermission?.granted ? (
          <Modal
            visible
            animationType="fade"
            onRequestClose={dismissScanner}
            statusBarTranslucent
          >
            <View style={styles.scannerModal} accessibilityViewIsModal>
              <CameraView
                testID="identity-qr-camera"
                style={StyleSheet.absoluteFill}
                facing="back"
                barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
                onBarcodeScanned={scanIdentityQr}
                onMountError={() => {
                  dismissScanner();
                  setScannerError("The camera could not start. You can still compare the safety number manually.");
                }}
              />
              <View pointerEvents="none" style={styles.scannerShade} />
              <View pointerEvents="none" style={styles.scannerFrame} />
              <View
                style={[
                  styles.scannerHeader,
                  {
                    paddingTop: insets.top + spacing.sm,
                    paddingLeft: Math.max(spacing.md, insets.left),
                    paddingRight: Math.max(spacing.md, insets.right),
                  },
                ]}
              >
                <Text accessibilityRole="header" style={styles.scannerTitle}>Scan identity QR</Text>
                <Pressable
                  accessibilityRole="button"
                  accessibilityLabel="Close QR scanner"
                  onPress={dismissScanner}
                  hitSlop={8}
                  style={styles.scannerClose}
                >
                  <X size={24} strokeWidth={2.2} color="white" />
                </Pressable>
              </View>
              <View pointerEvents="none" style={[styles.scannerInstructions, { paddingBottom: insets.bottom + spacing.lg }]}>
                <Text style={styles.scannerInstructionsText}>{"Center the QR code shown on the other person's Veil device. The camera closes after one scan."}</Text>
              </View>
            </View>
          </Modal>
        ) : null}
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
  headerSide: { width: 92, minHeight: 44, flexDirection: "row", alignItems: "center", gap: 2 },
  headerSideEnd: { justifyContent: "flex-end" },
  back: { flexShrink: 1, color: colors.primaryHi, fontSize: 13 },
  headerTitle: { flex: 1, color: colors.textHi, fontWeight: "800", letterSpacing: 1.4, textTransform: "uppercase", textAlign: "center", fontSize: 12 },
  content: { padding: spacing.md, gap: spacing.md }, section: { padding: spacing.md, borderRadius: radii.lg, borderWidth: StyleSheet.hairlineWidth, borderColor: colors.border, backgroundColor: "rgba(255,255,255,0.025)" },
  sectionTitle: { color: colors.textLo, fontSize: 10, fontWeight: "800", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: spacing.md }, person: { alignItems: "center" }, name: { color: colors.textHi, fontSize: 18, fontWeight: "800", marginTop: 10 }, username: { color: colors.textLo, fontSize: 12, marginTop: 2 }, about: { color: colors.textMd, fontSize: 13, lineHeight: 19, textAlign: "center", marginTop: 10 },
  profilePrivacy: { color: colors.textLo, fontSize: 10, lineHeight: 15, textAlign: "center", marginTop: 10 },
  detail: { marginTop: 8 }, detailLabel: { color: colors.textLo, fontSize: 10 }, detailValue: { color: colors.textHi, fontSize: 12, marginTop: 3 }, mono: { fontFamily: "monospace", fontSize: 11 },
  role: { alignSelf: "flex-start", marginTop: 12, paddingHorizontal: 9, paddingVertical: 4, borderRadius: radii.pill, borderWidth: 1, borderColor: colors.warningBorder, backgroundColor: colors.warningBg }, roleText: { color: colors.warning, fontSize: 10, textTransform: "uppercase", fontWeight: "800" },
  proofTitle: { color: colors.warning, fontSize: 14, fontWeight: "800" }, proofUnavailable: { color: "#f87171", fontSize: 14, fontWeight: "800" }, note: { color: colors.textLo, fontSize: 11, lineHeight: 17, marginTop: 8 },
  proofVerified: { color: "#6ee7b7" },
  fingerprintEmoji: { color: colors.textHi, fontSize: 20, lineHeight: 31, marginTop: 14, letterSpacing: 2 },
  qrCard: { alignSelf: "center", marginTop: 16, padding: 4, borderRadius: radii.md, backgroundColor: "white", overflow: "hidden" },
  verifyButton: { minHeight: 46, marginTop: 16, borderRadius: radii.md, backgroundColor: colors.primary, flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 8, paddingHorizontal: spacing.md },
  verifyButtonDisabled: { opacity: 0.55 },
  verifyButtonText: { color: "white", fontSize: 13, fontWeight: "800" },
  compareButton: { minHeight: 46, marginTop: 10, borderRadius: radii.md, borderWidth: 1, borderColor: colors.primary, flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 8, paddingHorizontal: spacing.md },
  compareButtonText: { color: colors.primaryHi, fontSize: 13, fontWeight: "800" },
  scanError: { color: "#fca5a5", fontSize: 11, lineHeight: 17, marginTop: 12 },
  settingsButton: { minHeight: 40, marginTop: 8, alignItems: "center", justifyContent: "center" },
  settingsButtonText: { color: colors.primaryHi, fontSize: 12, fontWeight: "700" },
  scannerModal: { flex: 1, backgroundColor: "#02060a" },
  scannerShade: { ...StyleSheet.absoluteFillObject, backgroundColor: "rgba(0,0,0,0.18)" },
  scannerFrame: { position: "absolute", width: 264, height: 264, borderRadius: 26, borderWidth: 3, borderColor: "white", alignSelf: "center", top: "31%" },
  scannerHeader: { position: "absolute", left: 0, right: 0, flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  scannerTitle: { color: "white", fontSize: 17, fontWeight: "800", textShadowColor: "rgba(0,0,0,0.8)", textShadowRadius: 5 },
  scannerClose: { width: 46, height: 46, borderRadius: 23, alignItems: "center", justifyContent: "center", backgroundColor: "rgba(0,0,0,0.55)" },
  scannerInstructions: { position: "absolute", left: spacing.lg, right: spacing.lg, bottom: 0 },
  scannerInstructionsText: { color: "white", fontSize: 13, lineHeight: 20, textAlign: "center", fontWeight: "600", textShadowColor: "rgba(0,0,0,0.8)", textShadowRadius: 5 },
  message: { minHeight: 48, borderRadius: radii.lg, backgroundColor: colors.primary, alignItems: "center", justifyContent: "center" }, messageText: { color: "white", fontSize: 14, fontWeight: "800" },
});
