import assert from "node:assert/strict";
import test from "node:test";

import {
  VerificationError,
  assertTesterBranding,
  assertTesterManifest,
  buildEvidence,
  parseApkSignerOutput,
  parseArguments,
  parseManifestXml,
  parseSingleLineOutput,
  verifyArchiveFileList,
  verifyTesterDataExtractionRules,
  verifyTesterPermissions,
  verifyTesterResourceBindings,
  verifyTesterSdkVersions,
} from "./verify-android-tester-apk.mjs";

const CERTIFICATE = "ab".repeat(32);
const FORBIDDEN_CERTIFICATE = "cd".repeat(32);
const OTHER_CERTIFICATE = "ef".repeat(32);
const SOURCE_COMMIT = "1a".repeat(20);
const BRANDING = Object.freeze({
  app_name: "Veil Tester",
  recovery_activity_label: "Veil Tester secure identity setup",
  recovery_brand: "VEIL TESTER · DIRECT PREVIEW",
});
const RESOURCES = Object.freeze({
  iconResource: "@drawable/ic_veil_tester_launcher",
  roundIconResource: "@drawable/ic_veil_tester_launcher",
  applicationLabelResource: "@string/app_name",
  recoveryActivityLabelResource: "@string/recovery_activity_label",
  dataExtractionRulesResource: "@xml/data_extraction_rules",
});
const BACKUP_EXCLUDED_DOMAINS = Object.freeze([
  "root",
  "file",
  "database",
  "sharedpref",
  "external",
  "device_root",
  "device_file",
  "device_database",
  "device_sharedpref",
]);
const DYNAMIC_RECEIVER_PERMISSION = (
  "io.veil.mobile.tester.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
);
const PERMISSIONS = Object.freeze([
  "android.permission.HIDE_OVERLAY_WINDOWS",
  "android.permission.INTERNET",
  "android.permission.POST_NOTIFICATIONS",
  "android.permission.USE_BIOMETRIC",
  "android.permission.USE_FINGERPRINT",
  "android.permission.VIBRATE",
  "android.permission.WAKE_LOCK",
  DYNAMIC_RECEIVER_PERMISSION,
]);
const BACKUP_POLICY = Object.freeze({
  dataExtractionRulesResource: "@xml/data_extraction_rules",
  cloudBackup: Object.freeze({
    disableIfNoEncryptionCapabilities: true,
    excludedDomains: BACKUP_EXCLUDED_DOMAINS,
  }),
  deviceTransfer: Object.freeze({
    excludedDomains: BACKUP_EXCLUDED_DOMAINS,
  }),
});
const COMPONENTS = Object.freeze([
  Object.freeze({
    type: "activity",
    name: "io.veil.mobile.MainActivity",
    enabled: true,
    exported: true,
    permission: null,
    authorities: null,
    grantUriPermissions: false,
  }),
  Object.freeze({
    type: "activity",
    name: "io.veil.mobile.recovery.RecoveryActivity",
    enabled: true,
    exported: false,
    permission: null,
    authorities: null,
    grantUriPermissions: false,
  }),
  Object.freeze({
    type: "service",
    name: "io.veil.mobile.push.VeilPushService",
    enabled: true,
    exported: false,
    permission: null,
    authorities: null,
    grantUriPermissions: false,
  }),
  Object.freeze({
    type: "provider",
    name: "expo.modules.filesystem.FileSystemFileProvider",
    enabled: true,
    exported: false,
    permission: null,
    authorities: "io.veil.mobile.tester.FileSystemFileProvider",
    grantUriPermissions: true,
  }),
  Object.freeze({
    type: "provider",
    name: "androidx.startup.InitializationProvider",
    enabled: true,
    exported: false,
    permission: null,
    authorities: "io.veil.mobile.tester.androidx-startup",
    grantUriPermissions: false,
  }),
  Object.freeze({
    type: "receiver",
    name: "androidx.profileinstaller.ProfileInstallReceiver",
    enabled: true,
    exported: true,
    permission: "android.permission.DUMP",
    authorities: null,
    grantUriPermissions: false,
  }),
]);
const BACKUP_MANIFEST_POLICY = Object.freeze({
  hasBackupAgent: false,
  backupOverrideAttributesPresent: Object.freeze([]),
});

function expectCode(action, expectedCode) {
  assert.throws(action, (error) => {
    assert.ok(error instanceof VerificationError);
    assert.equal(error.code, expectedCode);
    return true;
  });
}

function sdkArguments(overrides = {}) {
  const values = {
    "--android-sdk": "./fake-sdk",
    "--apk": "./app-tester.apk",
    "--evidence-out": "./tester-evidence.json",
    "--expected-cert-sha256": CERTIFICATE,
    "--forbidden-cert-sha256": FORBIDDEN_CERTIFICATE,
    "--expected-source-commit": SOURCE_COMMIT,
    "--expected-version-code": "42",
    "--expected-version-name": "0.2.0-tester",
    ...overrides,
  };
  return Object.entries(values).flat();
}

function signerOutput(digest = CERTIFICATE) {
  return [
    "Verifies",
    "Verified using v1 scheme (JAR signing): false",
    "Verified using v2 scheme (APK Signature Scheme v2): true",
    "Verified using v3 scheme (APK Signature Scheme v3): false",
    "Verified using v3.1 scheme (APK Signature Scheme v3.1): false",
    "Verified using v4 scheme (APK Signature Scheme v4): false",
    "Number of signers: 1",
    `Signer #1 certificate SHA-256 digest: ${digest}`,
    "Signer #1 certificate SHA-1 digest: 0000000000000000000000000000000000000000",
    "",
  ].join("\n");
}

function manifestXml({
  packageName = "io.veil.mobile.tester",
  cleartext = "false",
  allowBackup = "false",
  fullBackupContent = "false",
  dataExtractionRules = "@ref/0x7f140000",
  networkSecurityConfig = null,
  icon = "@ref/0x7f080123",
  roundIcon = "@ref/0x7f080123",
  applicationLabel = "@ref/0x7f110010",
  recoveryLabel = "@ref/0x7f110011",
  debuggable = "false",
  sourceCommit = SOURCE_COMMIT,
  extraMetadata = "",
  extraApplicationContent = "",
  omitMetadata = null,
} = {}) {
  const metadata = {
    "expo.modules.updates.ENABLED": "false",
    "io.veil.mobile.ALLOW_READY_SCREEN_CAPTURE": "false",
    "io.veil.mobile.BUILD_CHANNEL": "tester",
    "io.veil.mobile.ENROLLMENT_HTTPS_HOST": "tester.invalid",
    "io.veil.mobile.ENROLLMENT_SCHEME": "veil-tester",
    "io.veil.mobile.SOURCE_COMMIT": sourceCommit,
  };
  if (omitMetadata) delete metadata[omitMetadata];
  const metadataXml = Object.entries(metadata)
    .map(([name, value]) => `    <meta-data android:name="${name}" android:value="${value}" />`)
    .join("\n");
  const permissionXml = PERMISSIONS
    .map((name) => `  <uses-permission android:name="${name}" />`)
    .join("\n");
  return `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="42" android:versionName="0.2.0-tester" package="${packageName}">
  <queries>
    <intent>
      <data android:scheme="https" />
    </intent>
  </queries>
${permissionXml}
  <permission android:name="${DYNAMIC_RECEIVER_PERMISSION}" android:protectionLevel="0x2" />
  <application android:allowBackup="${allowBackup}" android:dataExtractionRules="${dataExtractionRules}" android:debuggable="${debuggable}" android:fullBackupContent="${fullBackupContent}" android:icon="${icon}" android:label="${applicationLabel}"${networkSecurityConfig === null ? "" : ` android:networkSecurityConfig="${networkSecurityConfig}"`} android:roundIcon="${roundIcon}" android:usesCleartextTraffic="${cleartext}">
${metadataXml}
${extraMetadata}
    <activity android:name="io.veil.mobile.MainActivity" android:exported="true" android:launchMode="2" android:screenOrientation="1">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="veil-tester" />
      </intent-filter>
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="tester.invalid" android:path="/enroll" />
      </intent-filter>
    </activity>
    <activity android:name="io.veil.mobile.recovery.RecoveryActivity" android:excludeFromRecents="true" android:exported="false" android:label="${recoveryLabel}" android:noHistory="false" android:stateNotNeeded="true" />
    <service android:name="io.veil.mobile.push.VeilPushService" android:exported="false" />
    <provider android:name="expo.modules.filesystem.FileSystemFileProvider" android:authorities="io.veil.mobile.tester.FileSystemFileProvider" android:exported="false" android:grantUriPermissions="true" />
    <provider android:name="androidx.startup.InitializationProvider" android:authorities="io.veil.mobile.tester.androidx-startup" android:exported="false" />
    <receiver android:name="androidx.profileinstaller.ProfileInstallReceiver" android:directBootAware="false" android:enabled="true" android:exported="true" android:permission="android.permission.DUMP" />
${extraApplicationContent}
  </application>
</manifest>
`;
}

function fileList(extra = [], omitted = []) {
  const entries = [
    "/",
    "/assets/",
    "/assets/index.android.bundle",
    "/lib/",
    "/lib/arm64-v8a/",
    "/lib/arm64-v8a/libveil_ffi.so",
    "/lib/x86_64/",
    "/lib/x86_64/libveil_ffi.so",
    "/classes.dex",
    ...extra,
  ].filter((entry) => !omitted.includes(entry));
  return `${entries.join("\n")}\n`;
}

function aapt2ResourceDump({
  iconId = "0x7f080123",
  iconName = "drawable/ic_veil_tester_launcher",
  iconFile = "res/drawable/ic_veil_tester_launcher.xml",
  applicationLabelId = "0x7f110010",
  applicationLabelName = "string/app_name",
  recoveryLabelId = "0x7f110011",
  recoveryLabelName = "string/recovery_activity_label",
  dataExtractionRulesId = "0x7f140000",
  dataExtractionRulesName = "xml/data_extraction_rules",
  dataExtractionRulesFile = "res/xml/data_extraction_rules.xml",
  extraResources = "",
} = {}) {
  return `Binary APK
Package name=io.veil.mobile.tester id=7f
  type drawable id=08 entryCount=2
    resource ${iconId} ${iconName}
      () (file) ${iconFile} type=XML
  type string id=11 entryCount=2
    resource ${applicationLabelId} ${applicationLabelName}
      () "Veil Tester"
    resource ${recoveryLabelId} ${recoveryLabelName}
      () "Veil Tester secure identity setup"
  type xml id=14 entryCount=1
    resource ${dataExtractionRulesId} ${dataExtractionRulesName}
      () (file) ${dataExtractionRulesFile} type=XML
${extraResources}`;
}

function dataExtractionRulesDump() {
  const excludeLines = (domain) => `        E: exclude (line=4)
          A: domain="${domain}" (Raw: "${domain}")
          A: path="." (Raw: ".")`;
  return `E: data-extraction-rules (line=2)
    E: cloud-backup (line=3)
      A: disableIfNoEncryptionCapabilities=true
${BACKUP_EXCLUDED_DOMAINS.map(excludeLines).join("\n")}
    E: device-transfer (line=10)
${BACKUP_EXCLUDED_DOMAINS.map(excludeLines).join("\n")}
`;
}

test("parseArguments accepts SDK mode and canonical expectations", () => {
  const parsed = parseArguments(sdkArguments());
  assert.equal(parsed.toolMode, "android-sdk");
  assert.equal(parsed.versionCode, 42);
  assert.equal(parsed.versionName, "0.2.0-tester");
  assert.equal(parsed.certificateSha256, CERTIFICATE);
  assert.equal(parsed.forbiddenCertificateSha256, FORBIDDEN_CERTIFICATE);
  assert.equal(parsed.sourceCommit, SOURCE_COMMIT);
  assert.ok(parsed.apkPath.endsWith("app-tester.apk"));
  assert.equal(
    parseArguments(sdkArguments({
      "--expected-version-name": "0.2.0-tester.20260720.1",
    })).versionName,
    "0.2.0-tester.20260720.1",
  );
});

test("parseArguments accepts exactly three explicit tool paths", () => {
  const args = sdkArguments();
  args.splice(args.indexOf("--android-sdk"), 2);
  args.push(
    "--aapt2-path",
    "./sdk/aapt2",
    "--apksigner-path",
    "./sdk/apksigner",
    "--apkanalyzer-path",
    "./sdk/apkanalyzer",
  );
  const parsed = parseArguments(args);
  assert.equal(parsed.toolMode, "explicit-paths");
  assert.ok(parsed.aapt2Path.endsWith("aapt2"));
  assert.ok(parsed.apksignerPath.endsWith("apksigner"));
});

test("parseArguments rejects unknown, duplicate, missing, and mixed tool arguments", () => {
  expectCode(() => parseArguments([...sdkArguments(), "--mystery", "x"]), "ARGS_UNKNOWN");
  expectCode(
    () => parseArguments([...sdkArguments(), "--apk", "other.apk"]),
    "ARGS_DUPLICATE",
  );
  expectCode(
    () => parseArguments(sdkArguments({ "--evidence-out": undefined }).filter((value) => value !== undefined)),
    "ARGS_SHAPE",
  );
  expectCode(
    () => parseArguments([...sdkArguments(), "--apksigner-path", "./apksigner"]),
    "ARGS_TOOL_MODE",
  );
  const missingAapt2 = sdkArguments();
  missingAapt2.splice(missingAapt2.indexOf("--android-sdk"), 2);
  missingAapt2.push(
    "--apksigner-path",
    "./sdk/apksigner",
    "--apkanalyzer-path",
    "./sdk/apkanalyzer",
  );
  expectCode(() => parseArguments(missingAapt2), "ARGS_TOOL_MODE");
});

test("parseArguments rejects noncanonical security identities", () => {
  const missingForbidden = sdkArguments();
  missingForbidden.splice(missingForbidden.indexOf("--forbidden-cert-sha256"), 2);
  expectCode(() => parseArguments(missingForbidden), "ARGS_REQUIRED");
  expectCode(
    () => parseArguments([
      ...sdkArguments(),
      "--forbidden-cert-sha256",
      FORBIDDEN_CERTIFICATE,
    ]),
    "ARGS_DUPLICATE",
  );
  expectCode(
    () => parseArguments(sdkArguments({ "--expected-cert-sha256": CERTIFICATE.toUpperCase() })),
    "ARGS_CERT_SHA256",
  );
  expectCode(
    () => parseArguments(sdkArguments({
      "--forbidden-cert-sha256": FORBIDDEN_CERTIFICATE.toUpperCase(),
    })),
    "ARGS_FORBIDDEN_CERT_SHA256",
  );
  expectCode(
    () => parseArguments(sdkArguments({ "--forbidden-cert-sha256": CERTIFICATE })),
    "ARGS_CERT_NOT_DISTINCT",
  );
  expectCode(
    () => parseArguments(sdkArguments({ "--expected-source-commit": SOURCE_COMMIT.toUpperCase() })),
    "ARGS_SOURCE_COMMIT",
  );
});

test("parseArguments rejects ambiguous version values and output collision", () => {
  for (const versionCode of ["0", "01", "2100000001", "1.0", "-1"]) {
    expectCode(
      () => parseArguments(sdkArguments({ "--expected-version-code": versionCode })),
      "ARGS_VERSION_CODE",
    );
  }
  for (const versionName of [
    " tester",
    "tester",
    "1.2-tester",
    "1.2.3",
    "1.2.3-tester.",
    `1.2.3-tester.${"a".repeat(33)}`,
    `${"1".repeat(60)}.2.3-tester`,
  ]) {
    expectCode(
      () => parseArguments(sdkArguments({ "--expected-version-name": versionName })),
      "ARGS_VERSION_NAME",
    );
  }
  expectCode(
    () => parseArguments(sdkArguments({ "--evidence-out": "./app-tester.apk" })),
    "ARGS_PATH_COLLISION",
  );
});

test("parseApkSignerOutput accepts one verified signer and normalizes colon hex", () => {
  const colonDigest = CERTIFICATE.match(/../g).join(":").toUpperCase();
  const parsed = parseApkSignerOutput(
    signerOutput(colonDigest),
    CERTIFICATE,
    FORBIDDEN_CERTIFICATE,
  );
  assert.deepEqual(parsed, {
    count: 1,
    certificateSha256: CERTIFICATE,
    signatureSchemePolicy: {
      v1: false,
      v2: true,
      v3: false,
      "v3.1": false,
      v4: false,
    },
  });
});

test("parseApkSignerOutput requires the explicit verification marker and v2=true", () => {
  expectCode(
    () => parseApkSignerOutput(
      signerOutput().replace("Verifies\n", ""),
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_NOT_VERIFIED",
  );
  expectCode(
    () => parseApkSignerOutput(
      signerOutput().replace(": true", ": false"),
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_SCHEME",
  );
  expectCode(
    () => parseApkSignerOutput(
      signerOutput().replace(
        "Verified using v2 scheme (APK Signature Scheme v2): true",
        "Verified using v2 scheme (APK Signature Scheme v2): true\nVerified using v2 scheme: false",
      ),
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_SCHEME",
  );
});

test("parseApkSignerOutput rejects a valid-looking v1-only APK", () => {
  const v1Only = signerOutput()
    .replace("Verified using v1 scheme (JAR signing): false", "Verified using v1 scheme (JAR signing): true")
    .replace("Verified using v2 scheme (APK Signature Scheme v2): true", "Verified using v2 scheme (APK Signature Scheme v2): false");
  expectCode(
    () => parseApkSignerOutput(v1Only, CERTIFICATE, FORBIDDEN_CERTIFICATE),
    "SIGNER_SCHEME",
  );
});

test("parseApkSignerOutput rejects v3 and v3.1 signing lineage", () => {
  for (const schemeLine of [
    "Verified using v3 scheme (APK Signature Scheme v3): false",
    "Verified using v3.1 scheme (APK Signature Scheme v3.1): false",
  ]) {
    expectCode(
      () => parseApkSignerOutput(
        signerOutput().replace(schemeLine, schemeLine.replace(": false", ": true")),
        CERTIFICATE,
        FORBIDDEN_CERTIFICATE,
      ),
      "SIGNER_SCHEME",
    );
  }
});

test("parseApkSignerOutput rejects every non-v2 scheme even when v2 verifies", () => {
  for (const schemeLine of [
    "Verified using v1 scheme (JAR signing): false",
    "Verified using v4 scheme (APK Signature Scheme v4): false",
  ]) {
    expectCode(
      () => parseApkSignerOutput(
        signerOutput().replace(schemeLine, schemeLine.replace(": false", ": true")),
        CERTIFICATE,
        FORBIDDEN_CERTIFICATE,
      ),
      "SIGNER_SCHEME",
    );
  }
});

test("parseApkSignerOutput rejects missing, duplicate, and unknown scheme rows", () => {
  expectCode(
    () => parseApkSignerOutput(
      signerOutput().replace("Verified using v4 scheme (APK Signature Scheme v4): false\n", ""),
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_SCHEME",
  );
  expectCode(
    () => parseApkSignerOutput(
      signerOutput().replace(
        "Verified using v4 scheme (APK Signature Scheme v4): false",
        "Verified using v4 scheme (APK Signature Scheme v4): false\nVerified using v4 scheme: false",
      ),
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_SCHEME",
  );
  expectCode(
    () => parseApkSignerOutput(
      signerOutput().replace(
        "Verified using v4 scheme (APK Signature Scheme v4): false",
        "Verified using v4 scheme (APK Signature Scheme v4): false\nVerified using v5 scheme: false",
      ),
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_SCHEME",
  );
});

test("parseApkSignerOutput rejects warnings even alongside a valid signature", () => {
  expectCode(
    () => parseApkSignerOutput(
      `${signerOutput()}WARNING: ignored entry\n`,
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_DIAGNOSTIC",
  );
});

test("parseApkSignerOutput rejects signer count and digest multiplicity tricks", () => {
  expectCode(
    () => parseApkSignerOutput(
      signerOutput().replace("Number of signers: 1", "Number of signers: 2"),
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_COUNT",
  );
  expectCode(
    () => parseApkSignerOutput(
      `${signerOutput()}Signer #1 certificate SHA-256 digest: ${CERTIFICATE}\n`,
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_DIGEST_COUNT",
  );
  expectCode(
    () => parseApkSignerOutput(
      signerOutput().replace("Signer #1 certificate", "Signer #2 certificate"),
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_DIGEST_FORMAT",
  );
});

test("parseApkSignerOutput rejects a different or malformed certificate", () => {
  expectCode(
    () => parseApkSignerOutput(
      signerOutput(FORBIDDEN_CERTIFICATE),
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_FORBIDDEN_CERTIFICATE",
  );
  expectCode(
    () => parseApkSignerOutput(
      signerOutput(OTHER_CERTIFICATE),
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_DIGEST_MISMATCH",
  );
  expectCode(
    () => parseApkSignerOutput(signerOutput("ab"), CERTIFICATE, FORBIDDEN_CERTIFICATE),
    "SIGNER_DIGEST_FORMAT",
  );
  expectCode(
    () => parseApkSignerOutput(signerOutput(), CERTIFICATE, CERTIFICATE),
    "SIGNER_CERT_NOT_DISTINCT",
  );
  expectCode(
    () => parseApkSignerOutput(
      `${signerOutput()}Source Stamp certificate SHA-256 digest: ${CERTIFICATE}\n`,
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_DIGEST_FORMAT",
  );
});

test("pure output parsers reject oversized and non-string fake output", () => {
  expectCode(
    () => parseApkSignerOutput(
      "x".repeat(256 * 1024 + 1),
      CERTIFICATE,
      FORBIDDEN_CERTIFICATE,
    ),
    "SIGNER_OUTPUT_SIZE",
  );
  expectCode(() => parseManifestXml(null), "MANIFEST_OUTPUT_SIZE");
  expectCode(() => verifyArchiveFileList(42), "FILES_OUTPUT_SIZE");
});

test("parseSingleLineOutput is exact and rejects multiline/control output", () => {
  assert.equal(parseSingleLineOutput("io.veil.mobile.tester\r\n"), "io.veil.mobile.tester");
  expectCode(() => parseSingleLineOutput("false\ntrue\n", "ONE"), "ONE");
  expectCode(() => parseSingleLineOutput("false\0\n", "ONE"), "ONE");
});

test("SDK verifier requires the reviewed Android compatibility boundary", () => {
  assert.deepEqual(verifyTesterSdkVersions("24\n", "35\n"), {
    minSdkVersion: 24,
    targetSdkVersion: 35,
  });
  expectCode(() => verifyTesterSdkVersions("23\n", "35\n"), "MIN_SDK_MISMATCH");
  expectCode(() => verifyTesterSdkVersions("24\n", "34\n"), "TARGET_SDK_MISMATCH");
  expectCode(() => verifyTesterSdkVersions("024\n", "35\n"), "MIN_SDK_MISMATCH");
  expectCode(() => verifyTesterSdkVersions("24\n", "35\n36\n"), "TARGET_SDK_OUTPUT");
});

test("effective permission verifier accepts only the reviewed exact set", () => {
  assert.deepEqual(verifyTesterPermissions(`${[...PERMISSIONS].reverse().join("\n")}\n`), PERMISSIONS);
  expectCode(
    () => verifyTesterPermissions(`${[...PERMISSIONS, PERMISSIONS[0]].join("\n")}\n`),
    "PERMISSIONS_DUPLICATE",
  );
  expectCode(
    () => verifyTesterPermissions(`${PERMISSIONS.slice(1).join("\n")}\n`),
    "PERMISSIONS_MISMATCH",
  );
  expectCode(
    () => verifyTesterPermissions(`${[...PERMISSIONS, "android.permission.CAMERA"].join("\n")}\n`),
    "PERMISSIONS_MISMATCH",
  );
  expectCode(() => verifyTesterPermissions("android.permission.INTERNET\0\n"), "PERMISSIONS_OUTPUT_FORMAT");
  expectCode(() => verifyTesterPermissions(null), "PERMISSIONS_OUTPUT_SIZE");
});

test("manifest parser accepts the exact tester boundary", () => {
  const parsed = parseManifestXml(manifestXml());
  const verified = assertTesterManifest(parsed, SOURCE_COMMIT, 42, "0.2.0-tester");
  assert.equal(verified.usesCleartextTraffic, false);
  assert.equal(verified.dataExtractionRulesResource, "@xml/data_extraction_rules");
  assert.equal(verified.metadata.SOURCE_COMMIT, SOURCE_COMMIT);
  assert.deepEqual(verified.components, COMPONENTS);
});

test("manifest parser binds exact version code and name when requested", () => {
  const parsed = parseManifestXml(manifestXml());
  expectCode(
    () => assertTesterManifest(parsed, SOURCE_COMMIT, 43, "0.2.0-tester"),
    "MANIFEST_VERSION_MISMATCH",
  );
  expectCode(
    () => assertTesterManifest(parsed, SOURCE_COMMIT, 42, "0.2.1-tester"),
    "MANIFEST_VERSION_MISMATCH",
  );
  expectCode(
    () => assertTesterManifest(parsed, SOURCE_COMMIT, 42),
    "MANIFEST_VERSION_EXPECTATION",
  );
});

test("manifest parser rejects missing or enabled cleartext policy", () => {
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml({ cleartext: "true" })), SOURCE_COMMIT),
    "MANIFEST_CLEARTEXT",
  );
  const missing = manifestXml().replace(' android:usesCleartextTraffic="false"', "");
  expectCode(
    () => assertTesterManifest(parseManifestXml(missing), SOURCE_COMMIT),
    "MANIFEST_CLEARTEXT",
  );
});

test("manifest parser requires explicit backup and transfer controls", () => {
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml({ allowBackup: "true" })), SOURCE_COMMIT),
    "MANIFEST_ALLOW_BACKUP",
  );
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml({ fullBackupContent: "true" })), SOURCE_COMMIT),
    "MANIFEST_FULL_BACKUP",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(' android:allowBackup="false"', "")),
      SOURCE_COMMIT,
    ),
    "MANIFEST_ALLOW_BACKUP",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(' android:fullBackupContent="false"', "")),
      SOURCE_COMMIT,
    ),
    "MANIFEST_FULL_BACKUP",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml({ dataExtractionRules: "@xml/data_extraction_rules" })),
      SOURCE_COMMIT,
    ),
    "MANIFEST_DATA_EXTRACTION_RULES_REFERENCE",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(
        ' android:dataExtractionRules="@ref/0x7f140000"',
        "",
      )),
      SOURCE_COMMIT,
    ),
    "MANIFEST_DATA_EXTRACTION_RULES_REFERENCE",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml({ networkSecurityConfig: "@xml/network_security_config" })),
      SOURCE_COMMIT,
    ),
    "MANIFEST_NETWORK_SECURITY_CONFIG",
  );
  for (const override of [
    'android:backupAgent="io.veil.mobile.BackupAgent"',
    'android:backupInForeground="true"',
    'android:fullBackupOnly="true"',
    'android:hasFragileUserData="true"',
    'android:killAfterRestore="false"',
    'android:restoreAnyVersion="true"',
  ]) {
    expectCode(
      () => assertTesterManifest(parseManifestXml(manifestXml().replace(
        ' android:allowBackup="false"',
        ` ${override} android:allowBackup="false"`,
      )), SOURCE_COMMIT),
      "MANIFEST_BACKUP_OVERRIDE",
    );
  }
});

test("manifest parser requires matching packaged application icon references", () => {
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml({ icon: "@drawable/ic_veil_tester_launcher" })),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_ICON_REFERENCE",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml({ roundIcon: "@ref/0x7f080124" })),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_ICON_REFERENCE",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(' android:roundIcon="@ref/0x7f080123"', "")),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_ICON_REFERENCE",
  );
});

test("manifest parser requires distinct packaged application and recovery labels", () => {
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml({ applicationLabel: "@string/app_name" })),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_LABEL_REFERENCE",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml({ recoveryLabel: "@ref/0x7f110010" })),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_LABEL_REFERENCE",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(
        '<activity android:name="io.veil.mobile.MainActivity" android:exported="true" android:launchMode="2" android:screenOrientation="1">',
        '<activity android:name="io.veil.mobile.MainActivity" android:exported="true" android:launchMode="2" android:screenOrientation="1" android:label="@ref/0x7f110012">',
      )),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_LABEL_REFERENCE",
  );
});

test("manifest parser requires exact main and recovery activity security semantics", () => {
  const replacements = [
    ['android:name="io.veil.mobile.MainActivity" android:exported="true"',
      'android:name="io.veil.mobile.MainActivity" android:exported="false"',
      "MANIFEST_MAIN_ACTIVITY_POLICY"],
    ['android:excludeFromRecents="true"', 'android:excludeFromRecents="false"',
      "MANIFEST_RECOVERY_ACTIVITY_POLICY"],
    ['android:exported="false" android:label="', 'android:exported="true" android:label="',
      "MANIFEST_RECOVERY_ACTIVITY_POLICY"],
    ['android:noHistory="false"', 'android:noHistory="true"',
      "MANIFEST_RECOVERY_ACTIVITY_POLICY"],
    ['android:stateNotNeeded="true"', 'android:stateNotNeeded="false"',
      "MANIFEST_RECOVERY_ACTIVITY_POLICY"],
  ];
  for (const [from, to, code] of replacements) {
    expectCode(
      () => assertTesterManifest(parseManifestXml(manifestXml().replace(from, to)), SOURCE_COMMIT),
      code,
    );
  }

  const recovery = /    <activity android:name="io\.veil\.mobile\.recovery\.RecoveryActivity"[^\n]+\/>/;
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml().replace(recovery, "")), SOURCE_COMMIT),
    "MANIFEST_RECOVERY_ACTIVITY_POLICY",
  );
  expectCode(
    () => parseManifestXml(manifestXml().replace(recovery, (value) => `${value}\n${value}`)),
    "MANIFEST_RECOVERY_ACTIVITY_COUNT",
  );
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml().replace(
      "  </application>",
      '    <activity android:name="io.veil.mobile.MainActivity" android:exported="true" />\n  </application>',
    )), SOURCE_COMMIT),
    "MANIFEST_MAIN_ACTIVITY_POLICY",
  );
});

test("manifest parser requires the exact reviewed application component inventory", () => {
  const pushService = '    <service android:name="io.veil.mobile.push.VeilPushService" android:exported="false" />';
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml({
      extraApplicationContent: '    <service android:name="io.veil.mobile.UnexpectedService" android:exported="false" />',
    })), SOURCE_COMMIT),
    "MANIFEST_COMPONENT_INVENTORY",
  );
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml({
      extraApplicationContent: '    <activity-alias android:name="io.veil.mobile.Alias" android:exported="false" android:targetActivity="io.veil.mobile.MainActivity" />',
    })), SOURCE_COMMIT),
    "MANIFEST_COMPONENT_TYPE",
  );
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml().replace(
      pushService,
      `${pushService}\n${pushService}`,
    )), SOURCE_COMMIT),
    "MANIFEST_COMPONENT_DUPLICATE",
  );
  for (const unifiedPushComponent of [
    '    <activity android:name="org.unifiedpush.android.connector.internal.LinkActivity" />',
    '    <receiver android:name="org.unifiedpush.android.connector.internal.MessagingReceiverImpl" android:exported="true" />',
    '    <service android:name="org.unifiedpush.android.connector.internal.RaiseToForegroundService" android:exported="true" />',
  ]) {
    expectCode(
      () => assertTesterManifest(parseManifestXml(manifestXml({
        extraApplicationContent: unifiedPushComponent,
      })), SOURCE_COMMIT),
      "MANIFEST_COMPONENT_INVENTORY",
    );
  }
});

test("manifest parser pins every component security boundary", () => {
  const replacements = [
    ['android:name="io.veil.mobile.MainActivity" android:exported="true"',
      'android:name="io.veil.mobile.MainActivity" android:enabled="false" android:exported="true"'],
    ['android:launchMode="2" android:screenOrientation="1"',
      'android:allowTaskReparenting="true" android:launchMode="2" android:screenOrientation="1"'],
    ['android:launchMode="2" android:screenOrientation="1"',
      'android:documentLaunchMode="2" android:launchMode="2" android:screenOrientation="1"'],
    ['android:launchMode="2" android:screenOrientation="1"',
      'android:launchMode="2" android:screenOrientation="1" android:taskAffinity="io.veil.mobile"'],
    ['android:launchMode="2" android:screenOrientation="1"',
      'android:launchMode="2" android:screenOrientation="0"'],
    ['android:launchMode="2" android:screenOrientation="1"',
      'android:launchMode="2" android:screenOrientation="1" android:supportsPictureInPicture="true"'],
    ['android:launchMode="2" android:screenOrientation="1"',
      'android:launchMode="2" android:screenOrientation="1" android:showWhenLocked="true"'],
    ['android:launchMode="2" android:screenOrientation="1"',
      'android:launchMode="2" android:screenOrientation="1" android:turnScreenOn="true"'],
    ['android:name="io.veil.mobile.recovery.RecoveryActivity"',
      'android:name="io.veil.mobile.recovery.RecoveryActivity" android:permission="android.permission.INTERNET"'],
    ['android:name="io.veil.mobile.push.VeilPushService" android:exported="false"',
      'android:name="io.veil.mobile.push.VeilPushService" android:exported="true"'],
    ['android:name="io.veil.mobile.push.VeilPushService" android:exported="false"',
      'android:name="io.veil.mobile.push.VeilPushService" android:enabled="false" android:exported="false"'],
    ['android:name="io.veil.mobile.push.VeilPushService" android:exported="false"',
      'android:name="io.veil.mobile.push.VeilPushService" android:exported="false" android:foregroundServiceType="dataSync"'],
    ['android:name="io.veil.mobile.push.VeilPushService" android:exported="false"',
      'android:name="io.veil.mobile.push.VeilPushService" android:exported="false" android:stopWithTask="true"'],
    ['android:authorities="io.veil.mobile.tester.FileSystemFileProvider"',
      'android:authorities="io.veil.mobile.FileSystemFileProvider"'],
    ['android:exported="false" android:grantUriPermissions="true"',
      'android:exported="false" android:grantUriPermissions="false"'],
    ['android:exported="false" android:grantUriPermissions="true"',
      'android:exported="false" android:forceUriPermissions="true" android:grantUriPermissions="true"'],
    ['android:exported="false" android:grantUriPermissions="true"',
      'android:exported="false" android:grantUriPermissions="true" android:writePermission="android.permission.INTERNET"'],
    ['android:authorities="io.veil.mobile.tester.androidx-startup" android:exported="false"',
      'android:authorities="io.veil.mobile.tester.androidx-startup" android:exported="false" android:grantUriPermissions="true"'],
    ['android:directBootAware="false" android:enabled="true"',
      'android:directBootAware="true" android:enabled="true"'],
    ['android:enabled="true" android:exported="true"',
      'android:enabled="false" android:exported="true"'],
    ['android:exported="true" android:permission="android.permission.DUMP"',
      'android:exported="true" android:permission="android.permission.INTERNET"'],
  ];
  for (const [from, to] of replacements) {
    expectCode(
      () => assertTesterManifest(parseManifestXml(manifestXml().replace(from, to)), SOURCE_COMMIT),
      "MANIFEST_COMPONENT_SECURITY",
    );
  }

  const fileProvider = '    <provider android:name="expo.modules.filesystem.FileSystemFileProvider" android:authorities="io.veil.mobile.tester.FileSystemFileProvider" android:exported="false" android:grantUriPermissions="true" />';
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml().replace(
      fileProvider,
      fileProvider.replace(
        " />",
        '><path-permission android:path="/" android:readPermission="android.permission.INTERNET" /></provider>',
      ),
    )), SOURCE_COMMIT),
    "MANIFEST_PROVIDER_GRANT_POLICY",
  );
});

test("manifest parser requires exact permissions and signature declaration", () => {
  const internetPermission = '  <uses-permission android:name="android.permission.INTERNET" />';
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml().replace(
      internetPermission,
      `${internetPermission}\n${internetPermission}`,
    )), SOURCE_COMMIT),
    "MANIFEST_PERMISSION_DUPLICATE",
  );
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml().replace(
      internetPermission,
      '  <uses-permission android:name="android.permission.CAMERA" />',
    )), SOURCE_COMMIT),
    "MANIFEST_PERMISSIONS",
  );
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml().replace(
      internetPermission,
      '  <uses-permission android:maxSdkVersion="34" android:name="android.permission.INTERNET" />',
    )), SOURCE_COMMIT),
    "MANIFEST_PERMISSIONS",
  );

  const declaration = (
    `  <permission android:name="${DYNAMIC_RECEIVER_PERMISSION}" android:protectionLevel="0x2" />`
  );
  for (const replacement of [
    "",
    `  <permission android:name="${DYNAMIC_RECEIVER_PERMISSION}" android:protectionLevel="0x0" />`,
    '  <permission android:name="io.veil.mobile.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="0x2" />',
    `${declaration}\n${declaration}`,
  ]) {
    expectCode(
      () => assertTesterManifest(
        parseManifestXml(manifestXml().replace(declaration, replacement)),
        SOURCE_COMMIT,
      ),
      "MANIFEST_PERMISSION_DECLARATION",
    );
  }
});

test("manifest parser rejects a debuggable or wrong-package artifact", () => {
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml({ debuggable: "true" })), SOURCE_COMMIT),
    "MANIFEST_DEBUGGABLE",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml({ packageName: "io.veil.mobile" })),
      SOURCE_COMMIT,
    ),
    "MANIFEST_PACKAGE",
  );
});

test("manifest parser rejects identity, application, profiling, and instrumentation overrides", () => {
  for (const attribute of [
    'android:sharedUserId="io.veil.shared"',
    'android:sharedUserLabel="@ref/0x7f110010"',
    'android:sharedUserMaxSdkVersion="34"',
    'android:targetSandboxVersion="2"',
  ]) {
    expectCode(
      () => assertTesterManifest(parseManifestXml(manifestXml().replace(
        'package="io.veil.mobile.tester"',
        `${attribute} package="io.veil.mobile.tester"`,
      )), SOURCE_COMMIT),
      "MANIFEST_IDENTITY_OVERRIDE",
    );
  }
  for (const attribute of [
    'android:allowTaskReparenting="true"',
    'android:directBootAware="true"',
    'android:manageSpaceActivity="io.veil.mobile.MainActivity"',
    'android:permission="android.permission.INTERNET"',
    'android:process=":other"',
    'android:taskAffinity="io.veil.mobile"',
    'android:testOnly="true"',
  ]) {
    expectCode(
      () => assertTesterManifest(parseManifestXml(manifestXml().replace(
        ' android:allowBackup="false"',
        ` ${attribute} android:allowBackup="false"`,
      )), SOURCE_COMMIT),
      "MANIFEST_APPLICATION_SECURITY",
    );
  }
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml().replace(
      "    <activity",
      '    <profileable android:shell="true" />\n    <activity',
    )), SOURCE_COMMIT),
    "MANIFEST_PROFILEABLE",
  );
  expectCode(
    () => assertTesterManifest(parseManifestXml(manifestXml().replace(
      "  <application",
      '  <instrumentation android:name="io.veil.mobile.TestRunner" android:targetPackage="io.veil.mobile.tester" />\n  <application',
    )), SOURCE_COMMIT),
    "MANIFEST_INSTRUMENTATION",
  );
});

test("manifest parser requires every exact tester metadata value", () => {
  for (const name of [
    "expo.modules.updates.ENABLED",
    "io.veil.mobile.ALLOW_READY_SCREEN_CAPTURE",
    "io.veil.mobile.BUILD_CHANNEL",
    "io.veil.mobile.ENROLLMENT_HTTPS_HOST",
    "io.veil.mobile.ENROLLMENT_SCHEME",
    "io.veil.mobile.SOURCE_COMMIT",
  ]) {
    expectCode(
      () => assertTesterManifest(parseManifestXml(manifestXml({ omitMetadata: name })), SOURCE_COMMIT),
      "MANIFEST_METADATA_MISSING",
    );
  }
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace('android:value="tester"', 'android:value="debug"')),
      SOURCE_COMMIT,
    ),
    "MANIFEST_METADATA_VALUE",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(
        '<meta-data android:name="expo.modules.updates.ENABLED" android:value="false" />',
        '<meta-data android:name="expo.modules.updates.ENABLED" android:value="true" />',
      )),
      SOURCE_COMMIT,
    ),
    "MANIFEST_METADATA_VALUE",
  );
});

test("manifest parser rejects duplicate and resource/value metadata ambiguity", () => {
  expectCode(
    () => parseManifestXml(manifestXml({
      extraMetadata: '    <meta-data android:name="io.veil.mobile.BUILD_CHANNEL" android:value="tester" />',
    })),
    "MANIFEST_METADATA_DUPLICATE",
  );
  expectCode(
    () => parseManifestXml(manifestXml({
      extraMetadata: '    <meta-data android:name="OTHER" android:value="x" android:resource="@string/x" />',
    })),
    "MANIFEST_METADATA_AMBIGUOUS",
  );
});

test("manifest parser rejects unprefixed metadata impostors", () => {
  const xml = manifestXml({
    omitMetadata: "io.veil.mobile.BUILD_CHANNEL",
    extraMetadata: '    <meta-data android:name="BUILD_CHANNEL" android:value="tester" />',
  });
  expectCode(
    () => assertTesterManifest(parseManifestXml(xml), SOURCE_COMMIT),
    "MANIFEST_METADATA_MISSING",
  );
});

test("manifest parser requires exact tester enrollment intent filters", () => {
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace('android:scheme="veil-tester"', 'android:scheme="veil-other"')),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_SCHEME_HANDLER",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace('android:host="tester.invalid"', 'android:host="other.invalid"')),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_HTTPS_HANDLER",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace('android:path="/enroll"', 'android:path="/other"')),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_HTTPS_HANDLER",
  );
  const launcherFilter = `      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>`;
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(launcherFilter, "")),
      SOURCE_COMMIT,
    ),
    "MANIFEST_MAIN_INTENT_FILTERS",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(
        '<category android:name="android.intent.category.LAUNCHER" />',
        '<category android:name="android.intent.category.DEFAULT" />',
      )),
      SOURCE_COMMIT,
    ),
    "MANIFEST_MAIN_INTENT_FILTERS",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(
        "    </activity>",
        `      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="evil.example" />
      </intent-filter>
    </activity>`,
      )),
      SOURCE_COMMIT,
    ),
    "MANIFEST_MAIN_INTENT_FILTERS",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(
        '<action android:name="android.intent.action.MAIN" />',
        '<action android:name="android.intent.action.MAIN" android:priority="1" />',
      )),
      SOURCE_COMMIT,
    ),
    "MANIFEST_MAIN_INTENT_FILTERS",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(
        '<data android:scheme="https" android:host="tester.invalid" android:path="/enroll" />',
        `<data android:scheme="https" android:host="tester.invalid" android:path="/enroll" />
        <uri-relative-filter-group android:allow="true">
          <data android:pathPrefix="/" />
        </uri-relative-filter-group>`,
      )),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_HTTPS_HANDLER",
  );
});

test("manifest parser rejects production enrollment handlers", () => {
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace('android:scheme="veil-tester"', 'android:scheme="veil"')),
      SOURCE_COMMIT,
    ),
    "MANIFEST_PRODUCTION_HANDLER",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace('android:host="tester.invalid"', 'android:host="veil.erez.pro"')),
      SOURCE_COMMIT,
    ),
    "MANIFEST_PRODUCTION_HANDLER",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml({
        extraApplicationContent: '    <meta-data android:name="UNRELATED"><data android:scheme="veil" /></meta-data>',
      })),
      SOURCE_COMMIT,
    ),
    "MANIFEST_PRODUCTION_HANDLER",
  );
});

test("manifest parser ignores generic HTTPS queries but rejects tester handlers on another activity", () => {
  assert.doesNotThrow(() => assertTesterManifest(parseManifestXml(manifestXml()), SOURCE_COMMIT));
  const otherActivity = `    <activity android:name="io.veil.mobile.OtherActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="veil-tester" />
      </intent-filter>
    </activity>`;
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml({ extraApplicationContent: otherActivity })),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_HANDLER_SCOPE",
  );
});

test("manifest parser rejects broadened tester filter structure", () => {
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(
        '<data android:scheme="veil-tester" />',
        '<data android:scheme="veil-tester" android:host="unexpected.invalid" />',
      )),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_SCHEME_HANDLER",
  );
  expectCode(
    () => assertTesterManifest(
      parseManifestXml(manifestXml().replace(
        '<intent-filter android:autoVerify="true">',
        '<intent-filter>',
      )),
      SOURCE_COMMIT,
    ),
    "MANIFEST_TESTER_HTTPS_HANDLER",
  );
});

test("manifest parser rejects declarations, unknown entities, duplicate attributes, and raw text", () => {
  expectCode(
    () => parseManifestXml(`<!DOCTYPE manifest>${manifestXml()}`),
    "MANIFEST_XML_DECLARATION",
  );
  expectCode(
    () => parseManifestXml(manifestXml().replace('android:value="tester"', 'android:value="test&#x65;r"')),
    "MANIFEST_XML_ENTITY",
  );
  expectCode(
    () => parseManifestXml(manifestXml().replace(
      'package="io.veil.mobile.tester"',
      'package="io.veil.mobile.tester" package="io.veil.mobile.tester"',
    )),
    "MANIFEST_XML_DUPLICATE_ATTRIBUTE",
  );
  expectCode(
    () => parseManifestXml(manifestXml().replace("</application>", "plaintext</application>")),
    "MANIFEST_XML_TEXT",
  );
});

test("manifest parser rejects malformed nesting and multiple applications", () => {
  expectCode(
    () => parseManifestXml(manifestXml().replace("</application>", "</manifest>")),
    "MANIFEST_XML_NESTING",
  );
  expectCode(
    () => parseManifestXml(manifestXml().replace("</manifest>", "<application /></manifest>")),
    "MANIFEST_APPLICATION_COUNT",
  );
});

test("aapt2 parser binds both manifest icon references to the exact tester drawable", () => {
  const parsed = parseManifestXml(manifestXml());
  assert.deepEqual(verifyTesterResourceBindings(parsed, aapt2ResourceDump()), RESOURCES);
  assert.deepEqual(verifyTesterResourceBindings(parsed, aapt2ResourceDump({
    extraResources: `    resource 0x7f080124 drawable/ic_veil_launcher
      () (file) res/drawable/ic_veil_launcher.xml type=XML
`,
  })), RESOURCES);
});

test("aapt2 parser rejects production, ambiguous, or unbacked tester icon bindings", () => {
  const parsed = parseManifestXml(manifestXml());
  expectCode(
    () => verifyTesterResourceBindings(parsed, aapt2ResourceDump({
      iconName: "drawable/ic_veil_launcher",
      iconFile: "res/drawable/ic_veil_launcher.xml",
    })),
    "AAPT2_PRODUCTION_ICON_BINDING",
  );
  expectCode(
    () => verifyTesterResourceBindings(parsed, aapt2ResourceDump({
      iconName: "drawable/unrelated",
      iconFile: "res/drawable/unrelated.xml",
    })),
    "AAPT2_TESTER_ICON_BINDING",
  );
  expectCode(
    () => verifyTesterResourceBindings(parsed, aapt2ResourceDump({ iconFile: "res/drawable/wrong.xml" })),
    "AAPT2_TESTER_ICON_FILE",
  );
  expectCode(
    () => verifyTesterResourceBindings(parsed, aapt2ResourceDump({
      extraResources: `    resource 0x7f080123 drawable/ic_veil_tester_launcher
      () (file) res/drawable/ic_veil_tester_launcher.xml type=XML
`,
    })),
    "AAPT2_ICON_ID_MAPPING",
  );
  expectCode(
    () => verifyTesterResourceBindings(parsed, aapt2ResourceDump({
      extraResources: `    resource 0x7f080124 drawable/ic_veil_tester_launcher
      () (file) res/drawable/ic_veil_tester_launcher.xml type=XML
`,
    })),
    "AAPT2_TESTER_ICON_BINDING",
  );
});

test("aapt2 parser binds application and recovery labels to their exact string names", () => {
  const parsed = parseManifestXml(manifestXml());
  expectCode(
    () => verifyTesterResourceBindings(parsed, aapt2ResourceDump({
      applicationLabelName: "string/other_app_name",
    })),
    "AAPT2_APP_LABEL_BINDING",
  );
  expectCode(
    () => verifyTesterResourceBindings(parsed, aapt2ResourceDump({
      recoveryLabelName: "string/other_recovery_label",
    })),
    "AAPT2_RECOVERY_LABEL_BINDING",
  );
  expectCode(
    () => verifyTesterResourceBindings(parsed, aapt2ResourceDump({
      extraResources: `    resource 0x7f110012 string/app_name
      () "Veil Tester"
`,
    })),
    "AAPT2_APP_LABEL_BINDING",
  );
});

test("aapt2 parser binds data extraction rules to the exact packaged XML", () => {
  const parsed = parseManifestXml(manifestXml());
  expectCode(
    () => verifyTesterResourceBindings(parsed, aapt2ResourceDump({
      dataExtractionRulesName: "xml/permissive_rules",
    })),
    "AAPT2_DATA_EXTRACTION_RULES_BINDING",
  );
  expectCode(
    () => verifyTesterResourceBindings(parsed, aapt2ResourceDump({
      dataExtractionRulesFile: "res/xml/permissive_rules.xml",
    })),
    "AAPT2_DATA_EXTRACTION_RULES_FILE",
  );
  expectCode(
    () => verifyTesterResourceBindings(parsed, aapt2ResourceDump({
      extraResources: `    resource 0x7f140001 xml/data_extraction_rules
      () (file) res/xml/data_extraction_rules.xml type=XML
`,
    })),
    "AAPT2_DATA_EXTRACTION_RULES_BINDING",
  );
});

test("aapt2 parser rejects wrong packages and malformed or unbounded fake output", () => {
  const parsed = parseManifestXml(manifestXml());
  expectCode(
    () => verifyTesterResourceBindings(
      parsed,
      aapt2ResourceDump().replace("io.veil.mobile.tester", "io.veil.mobile"),
    ),
    "AAPT2_RESOURCE_PACKAGE",
  );
  expectCode(
    () => verifyTesterResourceBindings(parsed, aapt2ResourceDump().replace("Binary APK", "Binary\0 APK")),
    "AAPT2_RESOURCE_OUTPUT_FORMAT",
  );
  expectCode(
    () => verifyTesterResourceBindings(parsed, null),
    "AAPT2_RESOURCE_OUTPUT_SIZE",
  );
});

test("branding parser requires the three exact tester strings", () => {
  assert.deepEqual(assertTesterBranding(BRANDING), BRANDING);
  expectCode(
    () => assertTesterBranding({ ...BRANDING, app_name: "Veil" }),
    "BRANDING_VALUE_MISMATCH",
  );
  const missing = { ...BRANDING };
  delete missing.recovery_brand;
  expectCode(() => assertTesterBranding(missing), "BRANDING_VALUES");
  expectCode(() => assertTesterBranding({ ...BRANDING, extra: "x" }), "BRANDING_VALUES");
});

test("data extraction rules require exact cloud and device-transfer exclusions", () => {
  assert.deepEqual(verifyTesterDataExtractionRules(dataExtractionRulesDump()), BACKUP_POLICY);

  for (const mutation of [
    (value) => value.replace('      A: disableIfNoEncryptionCapabilities=true\n', ""),
    (value) => value.replace('    E: device-transfer (line=10)\n', ""),
    (value) => value.replace('          A: domain="database" (Raw: "database")\n', ""),
    (value) => value.replace('          A: path="." (Raw: ".")', '          A: path="files" (Raw: "files")'),
    (value) => value.replace('    E: device-transfer (line=10)', '    E: device-transfer (line=10)\n      A: unexpected=true'),
    (value) => `${value}    E: extra-policy (line=20)\n`,
  ]) {
    expectCode(
      () => verifyTesterDataExtractionRules(mutation(dataExtractionRulesDump())),
      "DATA_EXTRACTION_RULES_POLICY",
    );
  }
});

test("data extraction rules reject malformed and unbounded tool output", () => {
  expectCode(
    () => verifyTesterDataExtractionRules(dataExtractionRulesDump().replace(
      "data-extraction-rules",
      "data-extraction-\0rules",
    )),
    "DATA_EXTRACTION_RULES_OUTPUT_FORMAT",
  );
  expectCode(
    () => verifyTesterDataExtractionRules("x".repeat(256 * 1024 + 1)),
    "DATA_EXTRACTION_RULES_OUTPUT_SIZE",
  );
  expectCode(() => verifyTesterDataExtractionRules(null), "DATA_EXTRACTION_RULES_OUTPUT_SIZE");
});

test("archive parser accepts bundle plus exactly arm64-v8a and x86_64 veil FFI", () => {
  assert.deepEqual(verifyArchiveFileList(fileList()), {
    requiredAsset: "assets/index.android.bundle",
    veilFfiAbis: ["arm64-v8a", "x86_64"],
  });
});

test("archive parser rejects a missing or directory-only JS bundle", () => {
  expectCode(
    () => verifyArchiveFileList(fileList([], ["/assets/index.android.bundle"])),
    "FILES_BUNDLE_MISSING",
  );
  expectCode(
    () => verifyArchiveFileList(fileList(["/assets/index.android.bundle/"], ["/assets/index.android.bundle"])),
    "FILES_BUNDLE_MISSING",
  );
});

test("archive parser rejects missing and extra veil FFI ABIs", () => {
  expectCode(
    () => verifyArchiveFileList(fileList([], ["/lib/x86_64/libveil_ffi.so"])),
    "FILES_VEIL_FFI_ABIS",
  );
  expectCode(
    () => verifyArchiveFileList(fileList([
      "/lib/armeabi-v7a/",
      "/lib/armeabi-v7a/libveil_ffi.so",
    ])),
    "FILES_VEIL_FFI_ABIS",
  );
});

test("archive parser rejects disguised, duplicate, relative, and traversal entries", () => {
  expectCode(
    () => verifyArchiveFileList(fileList(["/assets/libveil_ffi.so"])),
    "FILES_VEIL_FFI_PATH",
  );
  expectCode(
    () => verifyArchiveFileList(fileList(["/assets/index.android.bundle"])),
    "FILES_DUPLICATE",
  );
  expectCode(
    () => verifyArchiveFileList(fileList(["relative.txt"])),
    "FILES_ENTRY_FORMAT",
  );
  expectCode(
    () => verifyArchiveFileList(fileList(["/lib/../evil.so"])),
    "FILES_ENTRY_FORMAT",
  );
});

test("evidence builder emits only the reviewed sanitized contract", () => {
  const evidence = buildEvidence({
    apkSha256: "ef".repeat(32),
    apkSizeBytes: 123456,
    certificateSha256: CERTIFICATE,
    forbiddenCertificateSha256: FORBIDDEN_CERTIFICATE,
    signatureSchemePolicy: {
      v1: false,
      v2: true,
      v3: false,
      "v3.1": false,
      v4: false,
    },
    branding: BRANDING,
    resources: RESOURCES,
    backupPolicy: BACKUP_POLICY,
    sdkVersions: { minSdkVersion: 24, targetSdkVersion: 35 },
    permissions: PERMISSIONS,
    components: COMPONENTS,
    backupManifestPolicy: BACKUP_MANIFEST_POLICY,
    versionCode: 42,
    versionName: "0.2.0-tester",
    sourceCommit: SOURCE_COMMIT,
    toolMode: "android-sdk",
    verifiedAtUtc: "2026-07-20T10:11:12.345Z",
  });
  assert.equal(evidence.schema, "veil.android-tester-apk-evidence.v1");
  assert.equal(evidence.manifest.applicationId, "io.veil.mobile.tester");
  assert.equal(evidence.manifest.debuggable, false);
  assert.equal(evidence.manifest.minSdkVersion, 24);
  assert.equal(evidence.manifest.targetSdkVersion, 35);
  assert.equal(evidence.manifest.hasNetworkSecurityConfig, false);
  assert.deepEqual(evidence.manifest.backupAndTransferPolicy, {
    allowBackupManifestFlag: false,
    fullBackupContentManifestValue: false,
    backupAgentManifestValue: null,
    backupOverrideAttributesPresent: [],
    dataExtractionRulesResource: "@xml/data_extraction_rules",
    cloudBackup: BACKUP_POLICY.cloudBackup,
    deviceTransfer: BACKUP_POLICY.deviceTransfer,
  });
  assert.equal("allowBackup" in evidence.manifest, false);
  assert.equal("fullBackupContent" in evidence.manifest, false);
  assert.deepEqual(evidence.manifest.componentInventory, COMPONENTS);
  assert.deepEqual(evidence.manifest.activities, {
    main: { exported: true },
    recovery: {
      exported: false,
      excludeFromRecents: true,
      stateNotNeeded: true,
      noHistory: false,
    },
  });
  assert.deepEqual(evidence.manifest.permissionPolicy, {
    requested: PERMISSIONS,
    declaredSignaturePermission: {
      name: DYNAMIC_RECEIVER_PERMISSION,
      protectionLevel: "signature",
    },
  });
  assert.equal(evidence.manifest.metadata.ENROLLMENT_HTTPS_HOST, "tester.invalid");
  assert.equal(evidence.manifest.metadata.EXPO_UPDATES_ENABLED, "false");
  assert.equal(evidence.signer.differentFromForbiddenCertificate, true);
  assert.deepEqual(evidence.signer.signatureSchemePolicy, {
    v1: false,
    v2: true,
    v3: false,
    "v3.1": false,
    v4: false,
  });
  assert.equal("forbiddenCertificateSha256" in evidence.signer, false);
  assert.deepEqual(evidence.branding, {
    iconResource: RESOURCES.iconResource,
    roundIconResource: RESOURCES.roundIconResource,
    applicationLabelResource: RESOURCES.applicationLabelResource,
    recoveryActivityLabelResource: RESOURCES.recoveryActivityLabelResource,
    ...BRANDING,
  });
  assert.equal(evidence.tools.aapt2Source, "android-sdk/build-tools/35.0.0");
  assert.deepEqual(evidence.contents.veilFfiAbis, ["arm64-v8a", "x86_64"]);
  const serialized = JSON.stringify(evidence);
  assert.doesNotMatch(serialized, /certificate DN|stdout|stderr|toolPath|apkPath/);
  assert.doesNotMatch(serialized, new RegExp(FORBIDDEN_CERTIFICATE));
});

test("evidence builder rejects malformed hashes, sizes, commits, and timestamps", () => {
  const valid = {
    apkSha256: "ef".repeat(32),
    apkSizeBytes: 1,
    certificateSha256: CERTIFICATE,
    forbiddenCertificateSha256: FORBIDDEN_CERTIFICATE,
    signatureSchemePolicy: {
      v1: false,
      v2: true,
      v3: false,
      "v3.1": false,
      v4: false,
    },
    branding: BRANDING,
    resources: RESOURCES,
    backupPolicy: BACKUP_POLICY,
    sdkVersions: { minSdkVersion: 24, targetSdkVersion: 35 },
    permissions: PERMISSIONS,
    components: COMPONENTS,
    backupManifestPolicy: BACKUP_MANIFEST_POLICY,
    versionCode: 42,
    versionName: "0.2.0-tester",
    sourceCommit: SOURCE_COMMIT,
    toolMode: "explicit-paths",
    verifiedAtUtc: "2026-07-20T10:11:12.345Z",
  };
  expectCode(() => buildEvidence({ ...valid, apkSha256: "bad" }), "EVIDENCE_APK_SHA256");
  expectCode(() => buildEvidence({ ...valid, apkSizeBytes: 0 }), "EVIDENCE_APK_SIZE");
  expectCode(
    () => buildEvidence({ ...valid, forbiddenCertificateSha256: "bad" }),
    "EVIDENCE_FORBIDDEN_CERT_SHA256",
  );
  expectCode(
    () => buildEvidence({ ...valid, forbiddenCertificateSha256: CERTIFICATE }),
    "EVIDENCE_CERT_NOT_DISTINCT",
  );
  expectCode(
    () => buildEvidence({
      ...valid,
      signatureSchemePolicy: { ...valid.signatureSchemePolicy, v3: true },
    }),
    "EVIDENCE_SIGNATURE_SCHEMES",
  );
  expectCode(
    () => buildEvidence({ ...valid, branding: { ...BRANDING, app_name: "Veil" } }),
    "BRANDING_VALUE_MISMATCH",
  );
  expectCode(
    () => buildEvidence({
      ...valid,
      resources: { ...RESOURCES, iconResource: "@drawable/ic_veil_launcher" },
    }),
    "EVIDENCE_TESTER_RESOURCES",
  );
  expectCode(
    () => buildEvidence({
      ...valid,
      backupPolicy: {
        ...BACKUP_POLICY,
        deviceTransfer: { excludedDomains: BACKUP_EXCLUDED_DOMAINS.slice(0, -1) },
      },
    }),
    "EVIDENCE_BACKUP_POLICY",
  );
  expectCode(
    () => buildEvidence({
      ...valid,
      sdkVersions: { minSdkVersion: 24, targetSdkVersion: 34 },
    }),
    "EVIDENCE_SDK_VERSIONS",
  );
  expectCode(
    () => buildEvidence({
      ...valid,
      permissions: [...PERMISSIONS, "android.permission.CAMERA"],
    }),
    "EVIDENCE_PERMISSIONS",
  );
  expectCode(
    () => buildEvidence({
      ...valid,
      components: COMPONENTS.map((component) => (
        component.name === "io.veil.mobile.push.VeilPushService"
          ? { ...component, exported: true }
          : component
      )),
    }),
    "EVIDENCE_COMPONENTS",
  );
  expectCode(
    () => buildEvidence({
      ...valid,
      backupManifestPolicy: {
        hasBackupAgent: true,
        backupOverrideAttributesPresent: [],
      },
    }),
    "EVIDENCE_BACKUP_MANIFEST_POLICY",
  );
  expectCode(() => buildEvidence({ ...valid, sourceCommit: "ABC" }), "EVIDENCE_SOURCE_COMMIT");
  expectCode(() => buildEvidence({ ...valid, versionCode: 0 }), "EVIDENCE_VERSION_CODE");
  expectCode(() => buildEvidence({ ...valid, versionName: " tester" }), "EVIDENCE_VERSION_NAME");
  expectCode(() => buildEvidence({ ...valid, versionName: "tester" }), "EVIDENCE_VERSION_NAME");
  expectCode(() => buildEvidence({ ...valid, toolMode: "ambient-path" }), "EVIDENCE_TOOL_MODE");
  expectCode(() => buildEvidence({ ...valid, verifiedAtUtc: "today" }), "EVIDENCE_TIMESTAMP");
});
