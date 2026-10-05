import type {
  TimelineMessage as DemoMessage,
  Delivery,
} from './conversationContract';
import { canGroup } from './messageGrouping';

/** MobileDirectMessageDelivery exposes sent, never delivered/read (veil-ffi). */
export function deliveryLabel(delivery?: Delivery): string {
  switch (delivery) {
    case 'accepted':
      return 'Отправлено';
    case 'queued':
      return 'В очереди';
    case 'failed':
      return 'Не отправлено';
    case 'unknown':
      return 'Подтверждение неизвестно';
    default:
      return '';
  }
}

/** Collapse only equal, ordinary facts within an existing author/time group.
 * Attention states, deleted rows, absent facts and different states break it.
 * Look ahead in the full source, not the virtualized/rendered window.
 */
export function showDelivery(
  current: DemoMessage,
  next?: DemoMessage,
): boolean {
  if (!current.own || current.deleted || !current.delivery) return false;
  if (current.delivery !== 'accepted') return true;
  return (
    !next ||
    next.deleted === true ||
    !canGroup(current, next) ||
    next.delivery !== current.delivery
  );
}
