import { expect, test } from '@jest/globals';
import { directoryEntry } from '../accountDirectory';
import type { DmConversation } from '../../stores/chat';
const dm: DmConversation = {id:'conversation',name:'A very long name',isGroup:false,color:'#fff',peerUserId:'peer',peerUsername:'peer',
  avatarIdentity:{canonicalServerOrigin:'https://veil.example:443',userId:'peer',username:'peer'}};
test('unavailable previews stay honest; no native unread, mute, pin or receipt facts are manufactured', () => {
  expect(directoryEntry(dm)).toMatchObject({preview:'История откроется после выбора чата', hasDraft:false});
  for (const field of ['unread','pinned','muted','read','delivered']) expect(directoryEntry(dm)).not.toHaveProperty(field);
});
test('own preview and scoped draft have distinct semantics, with no transformation of message contents', () => {
  expect(directoryEntry({...dm,lastMessage:'hello',lastDirection:'outgoing'}).preview).toBe('Вы: hello');
  expect(directoryEntry({...dm,lastMessage:'hello',lastDirection:'incoming'}).preview).toBe('hello');
  expect(directoryEntry({...dm,lastMessage:'hello'},'draft').preview).toBe('Черновик: draft');
});
