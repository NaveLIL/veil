import { act, renderHook } from '@testing-library/react-native';
import { AppState, type AppStateStatus } from 'react-native';
import { afterEach, beforeEach, expect, jest, test } from '@jest/globals';
import VeilRuntime, { type VeilMobileRuntimeSnapshot } from '../native/runtime';
import { useVeilRuntimeLifecycle } from './useVeilRuntimeLifecycle';
import { resetRuntimeGateStoreForTests, useRuntimeGateStore } from '../stores/runtime';
import { resetChatStoreForTests, useChatStore } from '../stores/chat';

jest.mock('../native/runtime', () => {
  const actual=jest.requireActual('../native/runtime') as object;
  return {...actual,__esModule:true,default:{getSnapshot:jest.fn(),subscribe:jest.fn(),lock:jest.fn()}};
});
const snapshot:VeilMobileRuntimeSnapshot={identityExists:true,runtimeRevision:1,directGeneration:1,directContentRevision:0,
  sessionState:'open',connectionState:'connected',directoryReady:true,secureSyncState:'history_synchronized',
  binding:{canonicalServerOrigin:'https://veil.erez.pro:443',userId:'11111111-1111-4111-8111-111111111111'},
  pendingAccessPass:null,publicFailureCodeV1:null,directConversations:[]};
const runtime=VeilRuntime as unknown as {getSnapshot:jest.Mock<()=>Promise<VeilMobileRuntimeSnapshot>>;lock:jest.Mock<()=>Promise<void>>;
  subscribe:jest.Mock<(listener:(value:VeilMobileRuntimeSnapshot)=>void)=>{remove:()=>void}>};
let change:(state:AppStateStatus)=>void;
let callbacks:((value:VeilMobileRuntimeSnapshot)=>void)[], removed:ReturnType<typeof jest.fn>[];
const settle=()=>act(async()=>{for(let i=0;i<8;i++)await Promise.resolve();});
beforeEach(()=>{
  resetRuntimeGateStoreForTests();resetChatStoreForTests();callbacks=[];removed=[];
  Object.defineProperty(AppState,'currentState',{configurable:true,value:'active'});
  jest.spyOn(AppState,'addEventListener').mockImplementation((_event,listener)=>{change=listener;return {remove:jest.fn()};});
  runtime.getSnapshot.mockReset().mockResolvedValue(snapshot);runtime.lock.mockReset().mockResolvedValue(undefined);
  runtime.subscribe.mockReset().mockImplementation(listener=>{callbacks.push(listener);const remove=jest.fn();removed.push(remove);return {remove};});
});
afterEach(()=>{jest.restoreAllMocks();});

test('background removes listener once, foreground reattaches once, stale event cannot clear the new scope',async()=>{
  const clear=jest.spyOn(useChatStore.getState(),'clearRenderableChat');
  const ui=renderHook(useVeilRuntimeLifecycle);await settle();
  expect(callbacks).toHaveLength(1);
  act(()=>{change('inactive');change('background');});await settle();
  expect(removed[0]).toHaveBeenCalledTimes(1);expect(runtime.lock).toHaveBeenCalledTimes(1);
  act(()=>{change('active');change('active');});await settle();
  expect(callbacks).toHaveLength(2);
  const epoch=useRuntimeGateStore.getState().epoch, count=clear.mock.calls.length;
  act(()=>callbacks[0]({...snapshot,runtimeRevision:99,sessionState:'locked',connectionState:'disconnected'}));
  expect(useRuntimeGateStore.getState().epoch).toBe(epoch);
  expect(useRuntimeGateStore.getState().snapshot?.sessionState).toBe('open');
  expect(clear.mock.calls).toHaveLength(count);
  ui.unmount();expect(removed[1]).toHaveBeenCalledTimes(1);
});

test('late bootstrap result after unmount cannot attach an orphan listener',async()=>{
  let resolve!:(snapshot:VeilMobileRuntimeSnapshot)=>void;
  runtime.getSnapshot.mockImplementationOnce(()=>new Promise(r=>{resolve=r;}));
  const ui=renderHook(useVeilRuntimeLifecycle);await settle();ui.unmount();
  await act(async()=>resolve(snapshot));await settle();
  expect(runtime.subscribe).not.toHaveBeenCalled();
});
