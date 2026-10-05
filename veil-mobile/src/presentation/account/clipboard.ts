import { NativeModules } from 'react-native';
/** Write-only UI bridge; invoked only by an explicit Copy action. */
export async function copyAccountText(text: string) {
  const module = NativeModules.VeilPresentationClipboard;
  if (!text || !module || typeof module.copyText !== 'function' || !(await module.copyText(text)))
    throw Error('Clipboard unavailable');
}
