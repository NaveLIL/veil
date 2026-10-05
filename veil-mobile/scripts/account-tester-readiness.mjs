import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

// Only public build inputs. Never reads Passes, identities, app data or keystores.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const checks = [
  ['native bridge', 'android/app/src/main/java/io/veil/mobile/MainApplication.kt'],
  ['shared account shell', 'src/presentation/account/AccountFrame.tsx'],
  ['native Direct adapter', 'src/presenters/directDesignAdapter.ts'],
  ['capability contract', 'src/interfacePreview/conversationContract.ts'],
  ['local appearance', 'src/presentation/appearance/AccountAppearance.tsx'],
  ['tester verifier', 'scripts/verify-android-tester-apk.mjs'],
];
let failed=false;
for (const [name,file] of checks) { const ok=fs.existsSync(path.join(root,file)); console.log(`${ok?'READY':'MISSING'}: ${name}`); failed ||= !ok; }
const nativeLibraries = path.join(root,'android/app/src/main/jniLibs');
console.log(`Native library directory: ${fs.existsSync(nativeLibraries)?'present':'build required'}`);
for (const key of ['VEIL_ANDROID_TESTER_KEYSTORE','VEIL_ANDROID_TESTER_KEYSTORE_PASSWORD','VEIL_ANDROID_TESTER_KEY_ALIAS','VEIL_ANDROID_TESTER_KEY_PASSWORD'])
  console.log(`${key}: ${process.env[key]?'configured (value hidden)':'not configured in this process'}`);
if (process.argv.includes('--device')) {
  const adb=process.env.VEIL_ADB_PATH || 'adb';
  const args=process.env.VEIL_ADB_PORT?['-P',process.env.VEIL_ADB_PORT]:[];
  const result=spawnSync(adb,[...args,'devices'],{encoding:'utf8',windowsHide:true});
  if (result.status!==0) {console.log('DEVICE CHECK UNAVAILABLE'); failed=true;}
  else console.log(result.stdout.trim());
}
console.log('Authenticated Direct E2E: NOT RUN by this read-only readiness check. Credential availability and prior exchange results are not assessed.');
console.log('A new authenticated test requires a usable official test Access Pass, test identities and the existing trust flow. This script does not authenticate.');
process.exitCode=failed?1:0;
