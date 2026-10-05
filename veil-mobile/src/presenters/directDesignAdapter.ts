import type {
  DirectMessageProjection,
  DirectMessageView,
  DirectMessageDelivery,
} from '../native/runtime';
import type {
  Delivery,
  TimelineMessage,
} from '../interfacePreview/conversationContract';
import { directTextCapabilities } from '../interfacePreview/conversationContract';

/** Existing mobile text contract only. This adapter creates no runtime/store/queue. */
function delivery(value: DirectMessageDelivery): Delivery {
  switch (value) {
    case 'sending':
      return 'queued';
    case 'sent':
      return 'accepted';
    case 'failed':
      return 'failed';
    case 'unknown':
      return 'unknown';
  }
}
export function directTimelineRow(message: DirectMessageView): TimelineMessage {
  const date =
    message.timestampMs === null ? null : new Date(message.timestampMs);
  const valid = date && Number.isFinite(date.getTime()) ? date : null;
  const own = message.direction === 'outgoing';
  return {
    id: message.stableUiId,
    text: message.text,
    own,
    time: valid
      ? `${String(valid.getHours()).padStart(2, '0')}:${String(valid.getMinutes()).padStart(2, '0')}`
      : '—',
    day: valid
      ? `${valid.getFullYear()}-${String(valid.getMonth() + 1).padStart(2, '0')}-${String(valid.getDate()).padStart(2, '0')}`
      : undefined,
    // Incoming Sent does not imply an outgoing receipt for the current user.
    delivery: own ? delivery(message.delivery) : undefined,
  };
}
export function directDesignProjection(projection: DirectMessageProjection) {
  return {
    source: 'native' as const,
    availability: projection.availability,
    capabilities: directTextCapabilities,
    messages:
      projection.availability === 'available'
        ? projection.messages.map(directTimelineRow)
        : [],
  };
}
