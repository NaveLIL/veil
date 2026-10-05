import { useCallback, useEffect, useRef, useState } from 'react';
import { Animated, PanResponder } from 'react-native';
import { motion } from './appearance';

/** All ordinary dismiss sources share one exit; scope teardown stays immediate. */
export function useSheetMotion(visible: boolean, reduceMotion: boolean, height: number, onClose: () => void) {
  const [presented, setPresented] = useState(visible);
  const [closing, setClosing] = useState(false);
  // A native Modal may paint before onShow reaches JS. Its very first frame
  // must already be offscreen, rather than flash in place and jump down.
  const translate = useRef(new Animated.Value(reduceMotion ? 0 : height)).current;
  const owner = useRef({ alive: true, revision: 0, closing: false, delivered: false, notify: false, entered: false });
  const latest = useRef({ visible, reduceMotion, height, onClose, presented });
  latest.current = { visible, reduceMotion, height, onClose, presented };
  const finish = useCallback((revision: number) => {
    const state = owner.current;
    if (!state.alive || state.revision !== revision || !state.closing || state.delivered) return;
    state.delivered = true; setPresented(false);
    if (state.notify && latest.current.visible) latest.current.onClose();
  }, []);
  const dismiss = useCallback((notify = true) => {
    const state = owner.current;
    if (!state.alive || state.closing || !latest.current.presented) return;
    state.closing = true; state.notify = notify;
    setClosing(true);
    const revision = ++state.revision;
    translate.stopAnimation();
    if (latest.current.reduceMotion) { finish(revision); return; }
    Animated.timing(translate, { toValue: latest.current.height, duration: motion.transitionDuration,
      useNativeDriver: true }).start(({ finished }) => { if (finished) finish(revision); });
  }, [finish, translate]);
  const show = useCallback(() => {
    const state = owner.current;
    if (!state.alive || state.closing || state.entered || !latest.current.visible) return;
    state.entered = true;
    translate.stopAnimation();
    if (latest.current.reduceMotion) translate.setValue(0);
    else Animated.timing(translate, { toValue: 0, duration: motion.transitionDuration,
      useNativeDriver: true }).start();
  }, [translate]);
  useEffect(() => {
    const state = owner.current;
    state.alive = true;
    return () => { state.alive = false; state.revision++; translate.stopAnimation(); };
  }, [translate]);
  useEffect(() => {
    const state = owner.current;
    if (visible) {
      const reverseExit = state.closing && !state.delivered;
      state.revision++; state.closing = false; state.delivered = false; state.notify = false;
      state.entered = reverseExit;
      setClosing(false);
      const revision = state.revision;
      setPresented(true);
      if (reverseExit && !latest.current.reduceMotion) translate.stopAnimation(value => {
        if (!state.alive || state.revision !== revision || state.closing || !latest.current.visible) return;
        translate.setValue(value);
        Animated.timing(translate, { toValue: 0, duration: motion.transitionDuration, useNativeDriver: true }).start();
      });
      else { translate.stopAnimation(); translate.setValue(latest.current.reduceMotion ? 0 : latest.current.height); }
    } else dismiss(false);
  }, [visible, dismiss, translate]);
  useEffect(() => {
    if (!reduceMotion) return;
    translate.stopAnimation();
    if (owner.current.closing) finish(owner.current.revision);
    else translate.setValue(0);
  }, [reduceMotion, finish, translate]);
  const cancelGesture = useCallback(() => {
    if (owner.current.closing) return;
    translate.stopAnimation();
    if (latest.current.reduceMotion) translate.setValue(0);
    else Animated.spring(translate, { toValue: 0, ...motion.spring, useNativeDriver: true }).start();
  }, [translate]);
  const pan = PanResponder.create({
    onMoveShouldSetPanResponder: (_, g) => !owner.current.closing && g.dy > 10 && Math.abs(g.dy) > Math.abs(g.dx),
    onPanResponderGrant: () => { if (!owner.current.closing) translate.stopAnimation(); },
    onPanResponderMove: (_, g) => { if (!owner.current.closing) translate.setValue(Math.max(0, g.dy)); },
    onPanResponderRelease: (_, g) => { if (g.vy < -0.25) cancelGesture(); else if (g.dy > 70 || g.vy > 0.6) dismiss(); else cancelGesture(); },
    onPanResponderTerminate: cancelGesture,
  });
  return { presented, backdropActive: presented && !closing, translate, panHandlers: pan.panHandlers, dismiss: () => dismiss(), onShow: show,
    back: (onBack?: () => void) => { if (!owner.current.closing) { if (onBack) onBack(); else dismiss(); } } };
}
