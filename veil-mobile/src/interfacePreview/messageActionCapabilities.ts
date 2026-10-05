import type { ConversationCapabilities, TimelineMessage } from './conversationContract';
import { designCapabilities } from './conversationContract';
export type MessageAction = 'reply' | 'copy' | 'edit' | 'delete';
export function availableActions(message: TimelineMessage, capabilities: ConversationCapabilities = designCapabilities): MessageAction[] {
  if (message.deleted) return [];
  const actions: MessageAction[] = [];
  if (capabilities.reply) actions.push('reply');
  if (capabilities.copy && message.text) actions.push('copy');
  if (message.own && message.delivery !== 'unknown') {
    if (capabilities.edit && message.text && message.transfer?.phase !== 'sending') actions.push('edit');
    if (capabilities.delete) actions.push('delete');
  }
  return actions;
}
