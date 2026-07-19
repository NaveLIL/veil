import React, { useMemo, useState } from "react";
import {
  Modal,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import {
  ChevronRight,
  Hash,
  MicOff,
  UsersRound,
  Volume2,
  X,
} from "lucide-react-native";

import { MobileHeader } from "../components/navigation/MobileHeader";
import { Island } from "../components/ui/Island";
import {
  DESIGN_CIRCLE_MESSAGES,
  DESIGN_MEMBERS,
  DESIGN_ROOM_MESSAGES,
  DESIGN_ROOMS,
  designRoom,
  type DesignPreviewMember,
  type DesignPreviewMessage,
  type DesignPreviewRoom,
} from "../designPreview/fixtures";
import { colors, radii, spacing } from "../lib/theme";
import type { DesignPreviewStackParamList } from "./navigation";

type CircleProps = NativeStackScreenProps<DesignPreviewStackParamList, "DesignCircle">;
type SpaceProps = NativeStackScreenProps<DesignPreviewStackParamList, "DesignSpace">;
type RoomProps = NativeStackScreenProps<DesignPreviewStackParamList, "DesignRoom">;

export function DesignCircleScreen({ navigation }: CircleProps) {
  const [membersOpen, setMembersOpen] = useState(false);
  return (
    <View testID="design-circle-screen" style={styles.root}>
      <MobileHeader
        title="Design Circle"
        subtitle="Circle · design preview"
        backAction={{ label: "Spaces", onPress: () => navigation.goBack() }}
        action={{ label: "Members", icon: UsersRound, onPress: () => setMembersOpen(true) }}
      />
      <DesignPreviewBanner text="Local-only Circle fixture · nothing is sent or encrypted" />
      <DemoConversation messages={DESIGN_CIRCLE_MESSAGES} composerLabel="Circle messaging is disabled in design preview" />
      <DesignMembersSheet visible={membersOpen} onClose={() => setMembersOpen(false)} context="Design Circle" />
    </View>
  );
}

export function DesignSpaceScreen({ navigation }: SpaceProps) {
  const [membersOpen, setMembersOpen] = useState(false);
  const insets = useSafeAreaInsets();
  const categories = useMemo(
    () => [...new Set(DESIGN_ROOMS.map((room) => room.category))],
    [],
  );

  return (
    <View testID="design-space-screen" style={styles.root}>
      <MobileHeader
        title="Design Space"
        subtitle="Space · design preview"
        backAction={{ label: "Spaces", onPress: () => navigation.goBack() }}
        action={{ label: "Members", icon: UsersRound, onPress: () => setMembersOpen(true) }}
      />
      <ScrollView
        contentContainerStyle={[
          styles.spaceContent,
          { paddingBottom: insets.bottom + spacing.md },
        ]}
        showsVerticalScrollIndicator={false}
      >
        <DesignPreviewBanner text="Local-only Space fixture · navigation and badge design" embedded />
        <Island variant="solid" glow={false} padding={spacing.md}>
          <View style={styles.spaceIdentity}>
            <View style={styles.spaceMark}><Text style={styles.spaceMarkText}>DS</Text></View>
            <View style={styles.spaceMeta}>
              <Text accessibilityRole="header" style={styles.spaceName}>Design Space</Text>
              <Text style={styles.spaceDescription}>A structured private place with members, roles and Rooms.</Text>
            </View>
          </View>
          <View style={styles.spaceFacts}>
            <Fact value={String(DESIGN_ROOMS.length)} label="Rooms" />
            <Fact value="4" label="Members" />
            <Fact value="3" label="Mentions" accent />
          </View>
        </Island>

        {categories.map((category) => (
          <View key={category}>
            <Text style={styles.category}>{category}</Text>
            <Island variant="solid" glow={false} padding={0}>
              {DESIGN_ROOMS.filter((room) => room.category === category).map((room, index) => (
                <RoomRow
                  key={room.id}
                  room={room}
                  divided={index > 0}
                  onPress={() => navigation.navigate("DesignRoom", { roomId: room.id })}
                />
              ))}
            </Island>
          </View>
        ))}
      </ScrollView>
      <DesignMembersSheet visible={membersOpen} onClose={() => setMembersOpen(false)} context="Design Space" />
    </View>
  );
}

export function DesignRoomScreen({ navigation, route }: RoomProps) {
  const [membersOpen, setMembersOpen] = useState(false);
  const room = designRoom(route.params.roomId);
  const messages = room ? DESIGN_ROOM_MESSAGES[room.id] ?? [] : [];

  if (!room) {
    return (
      <View style={styles.root}>
        <MobileHeader
          title="Room unavailable"
          subtitle="Design preview"
          backAction={{ label: "Rooms", onPress: () => navigation.goBack() }}
        />
      </View>
    );
  }

  if (room.kind === "voice") {
    return (
      <DesignVoiceRoomPreview
        room={room}
        membersOpen={membersOpen}
        onBack={() => navigation.goBack()}
        onOpenMembers={() => setMembersOpen(true)}
        onCloseMembers={() => setMembersOpen(false)}
      />
    );
  }

  return (
    <View testID="design-room-screen" style={styles.root}>
      <MobileHeader
        title={`# ${room.name}`}
        subtitle={`Design Space · ${room.topic}`}
        backAction={{ label: "Rooms", onPress: () => navigation.goBack() }}
        action={{ label: "Members", icon: UsersRound, onPress: () => setMembersOpen(true) }}
      />
      <DesignPreviewBanner text="Local-only Room fixture · no Sender Key state exists" />
      <DemoConversation messages={messages} composerLabel="Room messaging is disabled in design preview" />
      <DesignMembersSheet visible={membersOpen} onClose={() => setMembersOpen(false)} context={`# ${room.name}`} />
    </View>
  );
}

export function DesignPreviewBanner({
  text,
  embedded = false,
}: {
  text: string;
  embedded?: boolean;
}) {
  return (
    <View
      accessibilityRole="text"
      style={[styles.banner, embedded && styles.bannerEmbedded]}
    >
      <Text style={styles.bannerLabel}>DESIGN PREVIEW</Text>
      <Text style={styles.bannerText}>{text}</Text>
    </View>
  );
}

function RoomRow({
  room,
  divided,
  onPress,
}: {
  room: DesignPreviewRoom;
  divided: boolean;
  onPress: () => void;
}) {
  const VoiceOrTextIcon = room.kind === "voice" ? Volume2 : Hash;
  const previewParticipantCount = room.participantMemberIds?.length ?? 0;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={room.kind === "voice"
        ? `${room.name} Voice Room. Design preview; voice is unavailable`
        : `${room.name} Text Room. ${room.mentions} mentions`}
      onPress={onPress}
      style={({ pressed }) => [
        styles.roomRow,
        divided && styles.divider,
        pressed && styles.pressed,
      ]}
    >
      <View style={styles.roomHash}>
        <VoiceOrTextIcon
          size={17}
          strokeWidth={2}
          color={room.unread ? colors.textHi : colors.textLo}
        />
      </View>
      <View style={styles.roomMeta}>
        <Text numberOfLines={1} style={[styles.roomName, room.unread && styles.roomUnread]}>{room.name}</Text>
        <Text numberOfLines={1} style={styles.roomTopic}>
          {room.kind === "voice" ? `${previewParticipantCount} people in layout preview · ${room.topic}` : room.topic}
        </Text>
      </View>
      {room.kind === "voice" ? (
        <View style={styles.phaseBadge}><Text style={styles.phaseBadgeText}>PHASE 7</Text></View>
      ) : room.mentions > 0 ? (
        <View style={styles.mentionBadge}><Text style={styles.mentionText}>@{room.mentions}</Text></View>
      ) : room.unread ? <View accessibilityLabel="Unread" style={styles.unreadDot} /> : null}
      <ChevronRight size={19} strokeWidth={1.8} color={colors.textLo} />
    </Pressable>
  );
}

function DesignVoiceRoomPreview({
  room,
  membersOpen,
  onBack,
  onOpenMembers,
  onCloseMembers,
}: {
  room: DesignPreviewRoom;
  membersOpen: boolean;
  onBack: () => void;
  onOpenMembers: () => void;
  onCloseMembers: () => void;
}) {
  const insets = useSafeAreaInsets();
  const previewParticipants = (room.participantMemberIds ?? [])
    .map((memberId) => DESIGN_MEMBERS.find((member) => member.id === memberId))
    .filter((member): member is DesignPreviewMember => Boolean(member));

  return (
    <View testID="design-voice-room-screen" style={styles.root}>
      <MobileHeader
        title={room.name}
        subtitle="Voice Room · Preview"
        backAction={{ label: "Rooms", onPress: onBack }}
        action={{ label: "Members", icon: UsersRound, onPress: onOpenMembers }}
      />
      <ScrollView
        contentContainerStyle={[
          styles.voiceContent,
          { paddingBottom: insets.bottom + spacing.md },
        ]}
        showsVerticalScrollIndicator={false}
      >
        <DesignPreviewBanner
          text="Visual only · microphone, signaling, media and call encryption are not active"
          embedded
        />
        <Island variant="solid" glow={false} padding={spacing.lg}>
          <View style={styles.voiceHero}>
            <View style={styles.voiceIcon}>
              <Volume2 size={24} strokeWidth={1.9} color={colors.primaryHi} />
            </View>
            <Text accessibilityRole="header" style={styles.voiceTitle}>{room.name}</Text>
            <Text style={styles.voiceTopic}>{room.topic}</Text>
            <View
              accessibilityRole="button"
              accessibilityLabel="Join voice unavailable until Phase 7"
              accessibilityState={{ disabled: true }}
              style={styles.voiceUnavailable}
            >
              <MicOff size={17} strokeWidth={2} color={colors.textLo} />
              <Text style={styles.voiceUnavailableText}>Join voice · unavailable until Phase 7</Text>
            </View>
          </View>
        </Island>
        <Text style={styles.category}>People in layout preview</Text>
        <Island variant="solid" glow={false} padding={0}>
          {previewParticipants.map((member, index) => (
            <View key={member.id} style={[styles.voiceMember, index > 0 && styles.divider]}>
              <DemoAvatar member={member} size={40} />
              <View style={styles.memberMeta}>
                <Text style={styles.memberName}>{member.name}</Text>
                <Text style={styles.memberPresence}>{member.role} · {member.presence}</Text>
              </View>
              <View style={styles.previewOnlyBadge}>
                <Text style={styles.previewOnlyText}>PREVIEW</Text>
              </View>
            </View>
          ))}
        </Island>
        <Text style={styles.voiceNote}>
          These people are local fixtures. No microphone permission, connection or presence claim exists.
        </Text>
      </ScrollView>
      <DesignMembersSheet
        visible={membersOpen}
        onClose={onCloseMembers}
        context={`${room.name} Voice Room`}
      />
    </View>
  );
}

function DemoConversation({
  messages,
  composerLabel,
}: {
  messages: DesignPreviewMessage[];
  composerLabel: string;
}) {
  const insets = useSafeAreaInsets();
  return (
    <Island
      variant="solid"
      glow={false}
      padding={0}
      style={[styles.conversation, { marginBottom: insets.bottom + spacing.md }]}
    >
      <ScrollView contentContainerStyle={styles.messages} showsVerticalScrollIndicator={false}>
        {messages.map((message) => {
          const member = DESIGN_MEMBERS.find((candidate) => candidate.id === message.authorId)
            ?? DESIGN_MEMBERS[0];
          return (
            <View key={message.id} style={[styles.message, message.mentionsYou && styles.messageMention]}>
              <DemoAvatar member={member} size={34} />
              <View style={styles.messageBody}>
                <View style={styles.messageHead}>
                  <Text style={[styles.messageAuthor, { color: member.color }]}>{member.name}</Text>
                  <Text style={styles.messageTime}>{message.time}</Text>
                  {message.mentionsYou ? <Text style={styles.youBadge}>MENTION</Text> : null}
                </View>
                <Text style={styles.messageText}>{message.text}</Text>
              </View>
            </View>
          );
        })}
      </ScrollView>
      <View style={styles.composer}>
        <TextInput
          editable={false}
          accessibilityLabel={composerLabel}
          placeholder={composerLabel}
          placeholderTextColor={colors.textLo}
          style={styles.composerInput}
        />
        <View accessibilityLabel="Send unavailable in design preview" style={styles.sendDisabled}>
          <Text style={styles.sendText}>Send</Text>
        </View>
      </View>
    </Island>
  );
}

function DesignMembersSheet({
  visible,
  onClose,
  context,
}: {
  visible: boolean;
  onClose: () => void;
  context: string;
}) {
  const insets = useSafeAreaInsets();
  return (
    <Modal
      visible={visible}
      transparent
      animationType="slide"
      onRequestClose={onClose}
      statusBarTranslucent
    >
      <View style={styles.modal} accessibilityViewIsModal>
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Close members"
          onPress={onClose}
          style={[StyleSheet.absoluteFill, styles.scrim]}
        />
        <View style={[styles.sheet, { paddingBottom: insets.bottom + spacing.md }]}>
          <View style={styles.handle} />
          <View style={styles.sheetHeader}>
            <View>
              <Text accessibilityRole="header" style={styles.sheetTitle}>Members</Text>
              <Text style={styles.sheetSubtitle}>{context} · design preview</Text>
            </View>
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Close"
              onPress={onClose}
              style={styles.sheetClose}
            >
              <X size={22} strokeWidth={2} color={colors.textMd} />
            </Pressable>
          </View>
          {DESIGN_MEMBERS.map((member, index) => (
            <View key={member.id} style={[styles.memberRow, index > 0 && styles.divider]}>
              <DemoAvatar member={member} size={40} />
              <View style={styles.memberMeta}>
                <Text style={styles.memberName}>{member.name}</Text>
                <Text style={styles.memberPresence}>{member.presence}</Text>
              </View>
              <View style={styles.roleBadge}><Text style={styles.roleText}>{member.role}</Text></View>
            </View>
          ))}
          <Text style={styles.sheetNote}>Fixture members have no account IDs, identity keys, ACL or cryptographic authority.</Text>
        </View>
      </View>
    </Modal>
  );
}

function DemoAvatar({ member, size }: { member: DesignPreviewMember; size: number }) {
  return (
    <View
      accessibilityRole="image"
      accessibilityLabel={`${member.name} design preview avatar`}
      style={[
        styles.avatar,
        {
          width: size,
          height: size,
          borderRadius: Math.round(size * 0.36),
          borderColor: `${member.color}66`,
          backgroundColor: `${member.color}1F`,
        },
      ]}
    >
      <Text style={[styles.avatarText, { color: member.color, fontSize: Math.round(size * 0.3) }]}>{member.initials}</Text>
    </View>
  );
}

function Fact({ value, label, accent = false }: { value: string; label: string; accent?: boolean }) {
  return (
    <View style={styles.fact}>
      <Text style={[styles.factValue, accent && styles.factAccent]}>{value}</Text>
      <Text style={styles.factLabel}>{label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  banner: {
    marginHorizontal: spacing.md,
    marginBottom: spacing.xs,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    borderRadius: radii.md,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.warningBorder,
    backgroundColor: colors.warningBg,
  },
  bannerEmbedded: { marginHorizontal: 0, marginBottom: 0 },
  bannerLabel: { color: colors.warning, fontSize: 9, fontWeight: "900", letterSpacing: 1.3 },
  bannerText: { color: colors.textMd, fontSize: 10, lineHeight: 15, marginTop: 2 },
  conversation: { flex: 1, marginHorizontal: spacing.md, marginBottom: spacing.md },
  messages: { flexGrow: 1, padding: spacing.md, gap: spacing.md },
  message: { flexDirection: "row", gap: spacing.sm, padding: spacing.xs, borderRadius: radii.md },
  messageMention: { backgroundColor: "rgba(124,107,245,0.09)" },
  messageBody: { flex: 1, minWidth: 0 },
  messageHead: { flexDirection: "row", alignItems: "center", gap: spacing.sm },
  messageAuthor: { fontSize: 12, fontWeight: "800" },
  messageTime: { color: colors.textLo, fontSize: 9 },
  youBadge: { color: colors.primaryHi, fontSize: 8, fontWeight: "900", letterSpacing: 0.8 },
  messageText: { color: colors.textHi, fontSize: 13, lineHeight: 19, marginTop: 2 },
  composer: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    padding: spacing.sm,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: colors.border,
  },
  composerInput: {
    flex: 1,
    minHeight: 40,
    color: colors.textLo,
    fontSize: 11,
    paddingHorizontal: spacing.md,
    borderRadius: radii.lg,
    backgroundColor: colors.surfaceLow,
  },
  sendDisabled: {
    minHeight: 36,
    justifyContent: "center",
    paddingHorizontal: spacing.md,
    borderRadius: radii.pill,
    backgroundColor: colors.surfaceLow,
    opacity: 0.5,
  },
  sendText: { color: colors.textLo, fontSize: 10, fontWeight: "800" },
  spaceContent: { paddingHorizontal: spacing.md, paddingBottom: spacing.xxl, gap: spacing.md },
  spaceIdentity: { flexDirection: "row", alignItems: "center", gap: spacing.md },
  spaceMark: {
    width: 52,
    height: 52,
    alignItems: "center",
    justifyContent: "center",
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: "rgba(124,107,245,0.35)",
    backgroundColor: "rgba(124,107,245,0.12)",
  },
  spaceMarkText: { color: colors.primaryHi, fontSize: 16, fontWeight: "900" },
  spaceMeta: { flex: 1, minWidth: 0 },
  spaceName: { color: colors.textHi, fontSize: 17, fontWeight: "900" },
  spaceDescription: { color: colors.textMd, fontSize: 11, lineHeight: 16, marginTop: 3 },
  spaceFacts: { flexDirection: "row", marginTop: spacing.lg },
  fact: { flex: 1, alignItems: "center" },
  factValue: { color: colors.textHi, fontSize: 15, fontWeight: "900" },
  factAccent: { color: colors.primaryHi },
  factLabel: { color: colors.textLo, fontSize: 9, marginTop: 2 },
  category: { color: colors.textLo, fontSize: 9, fontWeight: "900", letterSpacing: 1.4, textTransform: "uppercase", marginLeft: spacing.sm, marginBottom: spacing.xs },
  roomRow: { minHeight: 58, flexDirection: "row", alignItems: "center", gap: spacing.sm, paddingHorizontal: spacing.md, paddingVertical: spacing.sm },
  roomHash: { width: 20, alignItems: "center", justifyContent: "center" },
  roomUnread: { color: colors.textHi, fontWeight: "800" },
  roomMeta: { flex: 1, minWidth: 0 },
  roomName: { color: colors.textMd, fontSize: 13, fontWeight: "600" },
  roomTopic: { color: colors.textLo, fontSize: 10, marginTop: 2 },
  mentionBadge: { minWidth: 27, height: 20, alignItems: "center", justifyContent: "center", paddingHorizontal: 6, borderRadius: radii.pill, backgroundColor: colors.primary },
  mentionText: { color: "white", fontSize: 9, fontWeight: "900" },
  phaseBadge: { paddingHorizontal: spacing.sm, paddingVertical: 4, borderRadius: radii.pill, backgroundColor: colors.surfaceLow },
  phaseBadgeText: { color: colors.textLo, fontSize: 8, fontWeight: "900", letterSpacing: 0.5 },
  unreadDot: { width: 7, height: 7, borderRadius: 4, backgroundColor: colors.textHi },
  divider: { borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: colors.borderSoft },
  pressed: { opacity: 0.65, backgroundColor: colors.surfaceLow },
  modal: { flex: 1, justifyContent: "flex-end" },
  scrim: { backgroundColor: "rgba(4,7,12,0.76)" },
  sheet: { backgroundColor: colors.surfaceSolid, borderTopLeftRadius: 24, borderTopRightRadius: 24, borderWidth: StyleSheet.hairlineWidth, borderColor: "rgba(124,107,245,0.28)", paddingHorizontal: spacing.md },
  handle: { width: 38, height: 4, borderRadius: 2, backgroundColor: colors.textXLo, alignSelf: "center", marginTop: spacing.sm },
  sheetHeader: { minHeight: 58, flexDirection: "row", alignItems: "center", justifyContent: "space-between", borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: colors.border },
  sheetClose: { width: 48, height: 48, alignItems: "center", justifyContent: "center" },
  sheetTitle: { color: colors.textHi, fontSize: 16, fontWeight: "900" },
  sheetSubtitle: { color: colors.textLo, fontSize: 10, marginTop: 2 },
  memberRow: { minHeight: 58, flexDirection: "row", alignItems: "center", gap: spacing.md, paddingVertical: spacing.sm },
  memberMeta: { flex: 1 },
  memberName: { color: colors.textHi, fontSize: 13, fontWeight: "700" },
  memberPresence: { color: colors.textLo, fontSize: 10, marginTop: 2 },
  roleBadge: { paddingHorizontal: spacing.sm, paddingVertical: 4, borderRadius: radii.pill, backgroundColor: colors.surfaceLow },
  roleText: { color: colors.textMd, fontSize: 9, fontWeight: "800" },
  sheetNote: { color: colors.textLo, fontSize: 9, lineHeight: 14, textAlign: "center", marginTop: spacing.sm },
  avatar: { alignItems: "center", justifyContent: "center", borderWidth: 1 },
  avatarText: { fontWeight: "900" },
  voiceContent: { paddingHorizontal: spacing.md, gap: spacing.md },
  voiceHero: { alignItems: "center" },
  voiceIcon: { width: 54, height: 54, alignItems: "center", justifyContent: "center", borderRadius: radii.xl, backgroundColor: "rgba(124,107,245,0.12)" },
  voiceTitle: { color: colors.textHi, fontSize: 18, fontWeight: "900", marginTop: spacing.md },
  voiceTopic: { color: colors.textMd, fontSize: 11, marginTop: spacing.xs },
  voiceUnavailable: { minHeight: 48, alignSelf: "stretch", flexDirection: "row", alignItems: "center", justifyContent: "center", gap: spacing.sm, marginTop: spacing.lg, borderRadius: radii.lg, backgroundColor: colors.surfaceLow },
  voiceUnavailableText: { color: colors.textLo, fontSize: 11, fontWeight: "700", textAlign: "center" },
  voiceMember: { minHeight: 62, flexDirection: "row", alignItems: "center", gap: spacing.md, paddingHorizontal: spacing.md, paddingVertical: spacing.sm },
  previewOnlyBadge: { paddingHorizontal: spacing.sm, paddingVertical: 4, borderRadius: radii.pill, backgroundColor: colors.warningBg, borderWidth: StyleSheet.hairlineWidth, borderColor: colors.warningBorder },
  previewOnlyText: { color: colors.warning, fontSize: 8, fontWeight: "900", letterSpacing: 0.5 },
  voiceNote: { color: colors.textLo, fontSize: 10, lineHeight: 16, textAlign: "center", paddingHorizontal: spacing.lg },
});
