import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { parseManifestXml } from './verify-android-tester-apk.mjs';
import { allowedSources, root, verifyPreviewSource } from './verify-design-preview-source.mjs';

// Positional arguments are public values only; signing credentials are never read.
const [apk, sdk, javaHome, commit, certificate, bundle, sourceMap, output] = process.argv.slice(2);
if (!output || !/^[0-9a-f]{40}$/.test(commit ?? '') || !/^[0-9a-f]{64}$/.test(certificate ?? '')) throw Error('Expected APK SDK JAVA_HOME sourceCommit certificateSha256 bundle sourceMap output');
verifyPreviewSource();
const java = path.join(javaHome, 'bin/java.exe');
const analyze = (...args) => execFileSync(java, ['-Dfile.encoding=UTF-8', `-Dcom.android.sdklib.toolsdir=${sdk}/cmdline-tools/19.0`, '-classpath', `${sdk}/cmdline-tools/19.0/lib/apkanalyzer-classpath.jar`, 'com.android.tools.apk.analyzer.ApkAnalyzerCli', ...args, apk], { encoding: 'utf8', windowsHide: true, maxBuffer: 40 * 1024 * 1024 });
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const manifest = analyze('manifest', 'print');
if (analyze('manifest', 'min-sdk').trim() !== '24' || analyze('manifest', 'target-sdk').trim() !== '35') throw Error('Preview SDK mismatch');
const parsed = parseManifestXml(manifest);
const a = parsed.applicationAttributes;
const m = parsed.manifestAttributes;
if (m.get('package') !== 'io.veil.mobile.designpreview' || m.get('android:versionCode') !== '2026100402' || m.get('android:versionName') !== '0.1.0-design.20261004.2') throw Error('Preview identity/version mismatch');
if (a.get('android:name') !== 'io.veil.mobile.designpreview.DesignApplication' || a.get('android:allowBackup') !== 'false' || a.get('android:fullBackupContent') !== 'false' || a.get('android:usesCleartextTraffic') !== 'false' || a.get('android:debuggable') === 'true' || a.has('android:sharedUserId')) throw Error('Preview application boundary mismatch');
if (m.has('android:sharedUserId') || parsed.applicationIntentData.length || parsed.instrumentationCount || parsed.profileableCount) throw Error('Account/enrollment/test surface not allowed');
const permissions = parsed.requestedPermissions.map(p => p.attributes.get('android:name'));
const permitted = 'io.veil.mobile.designpreview.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION';
if (permissions.some(p => p !== permitted)) throw Error(`Preview must be offline with no device capabilities: ${permissions}`);
if (parsed.metadata.get('io.veil.design.SOURCE_COMMIT') !== commit || parsed.metadata.get('io.veil.design.OFFLINE_FIXTURES_ONLY') !== 'true' || parsed.metadata.get('expo.modules.updates.ENABLED') !== 'false') throw Error('Preview metadata drift');
const activities = parsed.applicationComponents.filter(c => c.type === 'activity');
if (activities.length !== 1 || activities[0].name !== 'io.veil.mobile.designpreview.DesignActivity') throw Error('Unexpected preview activity');
const exported = parsed.applicationComponents.filter(c => c.attributes.get('android:exported') === 'true');
if (exported.some(c => c.name !== activities[0].name && !(c.type === 'receiver' && c.name === 'androidx.profileinstaller.ProfileInstallReceiver' && c.attributes.get('android:permission') === 'android.permission.DUMP'))) throw Error('Unexpected externally reachable component');
if (parsed.applicationComponents.some(c => /io\.veil\.mobile\.(?!designpreview)/.test(c.name ?? ''))) throw Error('Account native component present');
const signer = execFileSync(java, ['-jar', `${sdk}/build-tools/35.0.0/lib/apksigner.jar`, 'verify', '--verbose', '--print-certs', apk], { encoding: 'utf8', windowsHide: true });
if (!signer.includes('Verifies') || !signer.includes('Number of signers: 1') || !signer.includes(`Signer #1 certificate SHA-256 digest: ${certificate}`) || !/Verified using v2 scheme.*: true/.test(signer) || /Verified using v(?:1|3|3\.1|4) scheme.*: true/.test(signer) || /WARNING:|ERROR:/.test(signer)) throw Error('Preview signing mismatch');
const dex = analyze('dex', 'packages', '--defined-only');
const veilNames = [...dex.matchAll(/io\.veil(?:\.[A-Za-z0-9_$]+)+/g)].map(match => match[0]);
if (!veilNames.some(name => name === 'io.veil.mobile.designpreview.DesignActivity') || veilNames.some(name => name !== 'io.veil.mobile' && name !== 'io.veil.mobile.designpreview' && !name.startsWith('io.veil.mobile.designpreview.')) || /uniffi\.veil|veil_ffi|net\.sqlcipher|expo\.modules\.(?:camera|securestore)/.test(dex)) throw Error('Account/device-capability code packaged in preview DEX');
const activity = analyze('dex', 'code', '--class', 'io.veil.mobile.designpreview.DesignActivity');
if (!activity.includes('VeilDesign') || /Window;->(?:addFlags|setFlags|clearFlags)|setRecentsScreenshotEnabled|consumeEnrollment/.test(activity)) throw Error('Preview activity capture/entry drift');
const nativeHost = analyze('dex', 'code', '--class', 'io.veil.mobile.designpreview.DesignApplication$reactNativeHost$1');
if (!nativeHost.includes('MainReactPackage') || !nativeHost.includes('SafeAreaContextPackage') || !nativeHost.includes('SvgPackage') || !nativeHost.includes('DesignAppearancePackage') || /VeilMobileRuntime|VeilCrypto|ExpoModulesPackage|PackageList/.test(nativeHost)) throw Error('Preview native registration mismatch');
const map = JSON.parse(fs.readFileSync(sourceMap, 'utf8'));
const found = new Map();
map.sources.forEach((source, i) => {
  const normalized = source.replaceAll('\\', '/').replace(/^.*?veil-mobile\//, '').replace(/^(\.\.\/)+/, '').replace(/^\/+/, '');
  if (!source.includes('node_modules') && !['\u0000polyfill:external-require', '\u0000polyfill:assets-registry'].includes(source)) {
    if (!allowedSources.includes(normalized)) throw Error(`Unexpected application source in bundle: ${source}`);
    if (found.has(normalized)) throw Error('Duplicate application source in map');
    const content = map.sourcesContent?.[i];
    if (typeof content !== 'string' || content !== fs.readFileSync(path.join(root, normalized), 'utf8')) throw Error(`Bundle source differs: ${normalized}`);
    found.set(normalized, sha(content));
  }
});
if (found.size !== allowedSources.length) throw Error(`Incomplete source map: ${[...found.keys()]}`);
const packaged = JSON.parse(execFileSync(java, [path.join(root, 'scripts/VerifyDesignBundle.java'), apk, bundle], { encoding: 'utf8', windowsHide: true }));
const evidence = { schema: 'veil.design-preview-apk.v1', verified: true, sourceCommit: commit, applicationId: m.get('package'), versionName: m.get('android:versionName'), apkSha256: sha(fs.readFileSync(apk)), apkBytes: fs.statSync(apk).size, certificateSha256: certificate, permissions, noAccountDex: true, noEnrollment: true, defaultScreenshotPolicy: true, physicalScreenshotTested: false, nativeHostExplicitPackages: true, sources: Object.fromEntries(found), packaged, components: parsed.applicationComponents.map(c => ({ type: c.type, name: c.name, exported: c.attributes.get('android:exported') ?? null })), productionCaptureCodeChanged: false };
fs.writeFileSync(output, JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify(evidence));
