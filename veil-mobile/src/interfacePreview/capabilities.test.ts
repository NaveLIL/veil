import { expect, test } from '@jest/globals';
import { directTextCapabilities, designCapabilities, TimelineMessage } from './conversationContract';
import { availableActions } from './messageActionCapabilities';
const message: TimelineMessage={id:'client:x',text:'message',own:true,time:'12:00',delivery:'unknown'};
test('native actions cannot expose future transport methods; Unknown offers no resend/edit/delete', () => {
  expect(availableActions(message,directTextCapabilities)).toEqual(['copy']);
  for (const feature of ['reply','edit','delete','attachments','retry','receipts','loadOlder'] as const)
    expect(directTextCapabilities[feature]).toBe(false);
});
test('capabilities restrict the same action presentation independently of demo/native identity', () => {
  expect(availableActions({...message,delivery:'accepted'},designCapabilities)).toEqual(['reply','copy','edit','delete']);
  expect(availableActions({...message,delivery:'accepted'}, {...designCapabilities,reply:false,delete:false})).toEqual(['copy','edit']);
  expect(availableActions({...message,deleted:true},directTextCapabilities)).toEqual([]);
});
