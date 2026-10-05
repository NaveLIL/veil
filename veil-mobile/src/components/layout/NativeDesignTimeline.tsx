import React, { useCallback, useLayoutEffect, useMemo, useRef } from 'react';
import {
  FlatList,
  StyleSheet,
  Text,
  View,
  ViewToken,
} from 'react-native';
import { useDirectTimelinePresenter } from '../../presenters/directTimeline';
import { directTimelineRow } from '../../presenters/directDesignAdapter';
import type { Member } from '../../stores/chat';
import { useChatStore } from '../../stores/chat';
import type {
  TimelineConversation,
  TimelineMessage,
} from '../../interfacePreview/conversationContract';
import { ConversationSurface } from '../../interfacePreview/ConversationSurface';
import { MessageRow } from '../../interfacePreview/MessageRow';
import { canGroup } from '../../interfacePreview/messageGrouping';
import { showDelivery } from '../../interfacePreview/deliveryPresentation';
import { geometry } from '../../interfacePreview/appearance';
import { VeilState } from '../../interfacePreview/VeilState';
import { MessageActionsPanel } from '../../interfacePreview/MessageActionsPanel';
import { directTextCapabilities } from '../../interfacePreview/conversationContract';
import { useNativeMessageActions } from '../../presenters/useNativeMessageActions';
import { useDirectViewportOwner } from '../../presenters/useDirectViewportOwner';
import { UserAvatar } from '../identity/UserAvatar';
import { PublicFailureCard } from '../runtime/PublicFailureCard';
import { usePresentation } from '../../interfacePreview/PresentationContext';

/** Existing native/store authority -> approved presentation. Never imports demo models. */
export function NativeDesignTimeline({
  bottomInset = 0,
  leftInset = 0,
  rightInset = 0,
  showHeader = true,
  onBack,
  onOpenIdentity,
  embedded = false,
}: {
  bottomInset?: number;
  leftInset?: number;
  rightInset?: number;
  showHeader?: boolean;
  onBack?: () => void;
  onOpenIdentity?: (member: Member, handle: number | string) => void;
  embedded?: boolean;
}) {
  const p = useDirectTimelinePresenter();
  const ownsViewport = useDirectViewportOwner(p.scope);
  const peer = useChatStore((s) =>
    p.conversationId
      ? s.directMembersByConversation[p.conversationId]?.peer
      : undefined,
  );
  const { c, reduceMotion } = usePresentation();
  const list = useRef<FlatList<TimelineMessage>>(null);
  const following = useRef(true);
  const anchor = useRef<string | null>(null);
  const scope = useRef<string | null | undefined>(undefined);
  const messages = useMemo(
    () =>
      p.messages.map((message) =>
        directTimelineRow({
          messageId: message.id,
          stableUiId: message.stableUiId,
          clientMessageId: message.clientMessageId,
          serverMessageId: message.serverMessageId,
          text: message.text,
          timestampMs: message.timestampMs,
          direction: message.direction,
          delivery: message.delivery,
        }),
      ),
    [p.messages],
  );
  const chat: TimelineConversation = {
    id: p.conversationId ?? 'unavailable',
    name: p.title,
    initials: p.title.slice(0, 2),
    color: peer?.color ?? c.accent,
    username: peer?.username ?? '',
    unread: 0,
    kind: 'direct',
    messages,
  };
  const actions = useNativeMessageActions(p.scope, messages);
  const currentProjection = useRef({ messages, availability: p.projectionState });
  currentProjection.current = { messages, availability: p.projectionState };
  const restore = useCallback(() => {
    if (!ownsViewport()) return;
    const current = currentProjection.current;
    if (!current.messages.length || current.availability !== 'available') return;
    if (following.current) list.current?.scrollToEnd({ animated: false });
    else {
      const index = current.messages.findIndex(
        (message) => message.id === anchor.current,
      );
      if (index >= 0)
        list.current?.scrollToIndex({
          index,
          animated: false,
          viewPosition: 0,
        });
    }
  }, [ownsViewport]);
  useLayoutEffect(() => {
    if (scope.current === p.scope) return;
    scope.current = p.scope;
    const saved = p.scope
      ? useChatStore.getState().directViewports[p.scope]
      : undefined;
    following.current = saved?.following ?? true;
    anchor.current = saved?.anchorId ?? null;
  }, [p.scope]);
  const currentMessageIds = useRef(new Set<string>());
  currentMessageIds.current = new Set(messages.map((message) => message.id));
  const viewable = useMemo(() => {
    const owner = p.scope;
    return (
    ({ viewableItems }: { viewableItems: ViewToken<TimelineMessage>[] }) => {
      if (!ownsViewport() || scope.current !== owner) return;
      const first = viewableItems.find((item) => item.isViewable);
      if (first && currentMessageIds.current.has(first.item.id)) {
        anchor.current = first.item.id;
        if (scope.current)
          useChatStore
            .getState()
            .setDirectViewport(
              scope.current,
              anchor.current,
              following.current,
            );
      }
    }
    );
  }, [ownsViewport, p.scope]);
  const empty = !p.conversationId
    ? [
        'Choose a Direct conversation',
        'Encrypted history opens only after selection.',
      ]
    : p.projectionState === 'unavailable'
      ? [
          'Messages are unavailable',
          'Veil withheld the entire projection because it could not be verified.',
        ]
      : p.historyWaitExpired
        ? [
            'История пока не получена',
            'Проверка занимает больше времени, чем обычно. Можно проверить снова или вернуться к списку чатов.',
          ]
      : p.projectionState === 'available'
        ? [
            'No messages yet',
            'This immutable Direct history is securely synchronized.',
          ]
        : [
            'Opening encrypted history...',
            'Verifying this conversation with the native runtime.',
          ];
  return (
    <View
      testID="chat-island-wrap"
      style={[
        styles.wrap,
        {
          paddingBottom: embedded ? 0 : 12 + Math.max(0, bottomInset),
          paddingLeft: embedded ? 0 : Math.max(12, leftInset),
          paddingRight: embedded ? 0 : Math.max(12, rightInset),
        },
      ]}
    >
      <ConversationSurface
        chat={chat}
        c={c}
        visible
        mode="native"
        showHeader={showHeader && !!onBack}
        subtitle="Личный чат"
        headerAvatar={peer && <UserAvatar identityKey={peer.identityKey} canonicalServerOrigin={peer.canonicalServerOrigin}
          userId={peer.userId} technicalUsername={peer.username} size={36} />}
        draft={p.draft}
        blocked={!p.canCompose}
        pending={p.pending}
        notice={actions.notice || (p.busyElsewhere ? 'Завершается отправка в другом чате. Дождитесь её результата.' : '')}
        onDraft={p.setDraft}
        onSend={() => void p.sendDraft()}
        onBack={onBack ?? (() => {})}
        onProfile={
          peer
            ? (handle) => {
                if (handle) onOpenIdentity?.(peer, handle);
              }
            : undefined
        }
        banner={
          p.error ? (
            <View testID="direct-send-error">
              <PublicFailureCard code={p.error.publicFailureCodeV1} compact />
            </View>
          ) : undefined
        }
        history={
          <FlatList
            key={p.scope ?? 'unavailable'}
            ref={list}
            testID="direct-message-list"
            data={messages}
            extraData={actions.selected?.id}
            keyExtractor={(message) =>
              `${p.scope ?? 'unavailable'}\u0000${message.id}`
            }
            style={styles.flex}
            contentContainerStyle={styles.history}
            keyboardShouldPersistTaps="handled"
            keyboardDismissMode="on-drag"
            initialNumToRender={40}
            maxToRenderPerBatch={10}
            windowSize={7}
            maintainVisibleContentPosition={{ minIndexForVisible: 0 }}
            scrollEventThrottle={32}
            onViewableItemsChanged={viewable}
            viewabilityConfig={{ itemVisiblePercentThreshold: 10 }}
            onScroll={({
              nativeEvent: { contentOffset, contentSize, layoutMeasurement },
            }) => {
              if (
                ownsViewport() && scope.current === p.scope &&
                currentProjection.current.availability === 'available' &&
                currentProjection.current.messages.length
              ) {
                following.current =
                  contentSize.height -
                    layoutMeasurement.height -
                    contentOffset.y <=
                  48;
                if (p.scope)
                  useChatStore
                    .getState()
                    .setDirectViewport(
                      p.scope,
                      anchor.current,
                      following.current,
                    );
              }
            }}
            onContentSizeChange={restore}
            onScrollToIndexFailed={({ index, averageItemLength }) => {
              if (!ownsViewport() || currentProjection.current.availability !== 'available'
                || index < 0 || index >= currentProjection.current.messages.length) return;
              list.current?.scrollToOffset({
                offset: index * averageItemLength,
                animated: false,
              });
            }}
            ListHeaderComponent={messages.length ? <Text accessibilityLabel="Начало доступной истории"
              style={[styles.hint, { color: c.muted, paddingBottom: 20 }]}>Начало доступной истории</Text> : null}
            ListEmptyComponent={
              <VeilState c={c}
                kind={p.projectionState === 'unavailable' || p.historyWaitExpired ? 'unavailable' : p.projectionState === 'available' ? 'empty' : 'loading'}
                testID={p.projectionState === 'unavailable' ? 'direct-history-unavailable' : p.projectionState !== 'available' ? 'direct-history-loading' : undefined}
                title={empty[0]} detail={empty[1]}
                action={p.projectionState === 'unavailable' || p.historyWaitExpired ? {label:'Проверить снова', onPress:() => void p.reload()} : undefined} />
            }
            renderItem={({ item, index }) => {
              const native = p.messages[index];
              return (
                <MessageRow
                  item={item}
                  chat={chat}
                  c={c}
                  selected={actions.selected?.id === item.id}
                  onMessage={actions.open}
                  grouped={canGroup(messages[index - 1], item)}
                  showStatus={showDelivery(item, messages[index + 1])}
                  retryEnabled={false}
                  onRetry={() => {}}
                  avatar={
                    <UserAvatar
                      identityKey={native.author.identityKey}
                      canonicalServerOrigin={
                        native.author.canonicalServerOrigin
                      }
                      userId={native.author.userId}
                      technicalUsername={native.author.username}
                      size={34}
                    />
                  }
                  onAuthor={
                    onOpenIdentity
                      ? (handle) => onOpenIdentity(native.author, handle)
                      : undefined
                  }
                  deliveryDetail={
                    native.direction === 'outgoing' &&
                    native.deliveryPublicFailureCodeV1 ? (
                      <View
                        testID={`direct-delivery-failure-${native.stableUiId}`}
                      >
                        <PublicFailureCard
                          announce={false}
                          code={native.deliveryPublicFailureCodeV1}
                          compact
                        />
                      </View>
                    ) : undefined
                  }
                />
              );
            }}
          />
        }
      />
      {actions.selected && <MessageActionsPanel message={actions.selected} c={c} reduceMotion={reduceMotion}
        capabilities={directTextCapabilities} onClose={actions.close}
        onAction={action => { if (action === 'copy') void actions.copy(); }} />}
    </View>
  );
}
const styles = StyleSheet.create({
  flex: { flex: 1 },
  wrap: { flex: 1 },
  history: { paddingHorizontal: 14, paddingBottom: 20, flexGrow: 1 },
  empty: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24,
  },
  title: { fontSize: 16, textAlign: 'center' },
  hint: { fontSize: 14, lineHeight: 22, marginTop: 8, textAlign: 'center' },
  retry: {
    minHeight: geometry.touchTarget,
    justifyContent: 'center',
    paddingHorizontal: 16,
  },
});
