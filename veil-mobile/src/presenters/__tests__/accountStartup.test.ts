import { expect, test } from '@jest/globals';
import { accountStartupState } from '../accountStartup';
import type { VeilMobileRuntimeSnapshot } from '../../native/runtime';
const ready: VeilMobileRuntimeSnapshot = {identityExists:true,sessionState:'open',connectionState:'connected',
  directoryReady:true,secureSyncState:'history_synchronized',pendingAccessPass:null,publicFailureCodeV1:null,
  binding:{canonicalServerOrigin:'https://veil.example:443',userId:'11111111-1111-4111-8111-111111111111'},
  runtimeRevision:1,directGeneration:1,directContentRevision:0,directConversations:[]};
test('startup is loading until the authoritative runtime facts exist', () => {
  expect(accountStartupState('bootstrapping',null,false,null)).toBe('loading');
  expect(accountStartupState('ready',{...ready,connectionState:'connecting'},false,null)).toBe('loading');
  expect(accountStartupState('ready',{...ready,directoryReady:false},false,null)).toBe('loading');
});
test('ready requires the real gate; disconnected, locked and fatal configuration are distinct', () => {
  expect(accountStartupState('ready',ready,false,null)).toBe('ready');
  expect(accountStartupState('ready',{...ready,connectionState:'disconnected'},false,null)).toBe('unavailable');
  expect(accountStartupState('ready',ready,true,null)).toBe('locked');
  expect(accountStartupState('ready',{...ready,sessionState:'locked'},false,null)).toBe('locked');
  expect(accountStartupState('error',null,false,'VEIL-NODE-004')).toBe('configuration-error');
  expect(accountStartupState('error',null,false,'VEIL-RUNTIME-999')).toBe('recoverable-error');
});
