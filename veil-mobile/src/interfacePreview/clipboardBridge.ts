import { NativeModules } from 'react-native';

type ClipboardCapability = { copyText(text: string): Promise<boolean> };
const clipboard = NativeModules.VeilDesignClipboard as
  | ClipboardCapability
  | undefined;
/** Write only. No clipboard reads, account runtime or general native dispatch. */
export async function copyDemoText(text: string) {
  if (!clipboard || !text || text.length > 4000)
    throw new Error('Clipboard unavailable');
  if (!(await clipboard.copyText(text)))
    throw new Error('Clipboard unavailable');
}
