import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { Buffer } from "node:buffer";
import {
  copyFile,
  link,
  lstat,
  mkdtemp,
  open,
  realpath,
  rm,
  stat,
} from "node:fs/promises";
import { createReadStream } from "node:fs";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { pathToFileURL } from "node:url";
import { TextDecoder } from "node:util";

const BUILD_TOOLS_VERSION = "35.0.0";
const EXPECTED_APPLICATION_ID = "io.veil.mobile.tester";
const EXPECTED_MIN_SDK_VERSION = 24;
const EXPECTED_TARGET_SDK_VERSION = 35;
const MAIN_ACTIVITY_CLASS = "io.veil.mobile.MainActivity";
const RECOVERY_ACTIVITY_CLASS = "io.veil.mobile.recovery.RecoveryActivity";
const PUSH_SERVICE_CLASS = "io.veil.mobile.push.VeilPushService";
const FILE_SYSTEM_PROVIDER_CLASS = "expo.modules.filesystem.FileSystemFileProvider";
const INITIALIZATION_PROVIDER_CLASS = "androidx.startup.InitializationProvider";
const PROFILE_INSTALL_RECEIVER_CLASS = "androidx.profileinstaller.ProfileInstallReceiver";
const MAIN_ACTION = "android.intent.action.MAIN";
const VIEW_ACTION = "android.intent.action.VIEW";
const LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER";
const DEFAULT_CATEGORY = "android.intent.category.DEFAULT";
const BROWSABLE_CATEGORY = "android.intent.category.BROWSABLE";
const EXPECTED_ABIS = Object.freeze(["arm64-v8a", "x86_64"]);
const EXPECTED_METADATA = Object.freeze({
  "expo.modules.updates.ENABLED": "false",
  "io.veil.mobile.ALLOW_READY_SCREEN_CAPTURE": "false",
  "io.veil.mobile.BUILD_CHANNEL": "tester",
  "io.veil.mobile.ENROLLMENT_HTTPS_HOST": "tester.invalid",
  "io.veil.mobile.ENROLLMENT_SCHEME": "veil-tester",
});
const EXPECTED_BRANDING_RESOURCES = Object.freeze({
  app_name: "Veil Tester",
  recovery_activity_label: "Veil Tester secure identity setup",
  recovery_brand: "VEIL TESTER · DIRECT PREVIEW",
});
const EXPECTED_TESTER_ICON_RESOURCE = "@drawable/ic_veil_tester_launcher";
const EXPECTED_TESTER_ICON_TABLE_NAME = "drawable/ic_veil_tester_launcher";
const EXPECTED_TESTER_ICON_FILE = "res/drawable/ic_veil_tester_launcher.xml";
const PRODUCTION_ICON_TABLE_NAME = "drawable/ic_veil_launcher";
const EXPECTED_DATA_EXTRACTION_RULES_RESOURCE = "@xml/data_extraction_rules";
const EXPECTED_DATA_EXTRACTION_RULES_TABLE_NAME = "xml/data_extraction_rules";
const EXPECTED_DATA_EXTRACTION_RULES_FILE = "res/xml/data_extraction_rules.xml";
const EXPECTED_BACKUP_EXCLUDED_DOMAINS = Object.freeze([
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
  `${EXPECTED_APPLICATION_ID}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`
);
const EXPECTED_PERMISSIONS = Object.freeze([
  "android.permission.HIDE_OVERLAY_WINDOWS",
  "android.permission.INTERNET",
  "android.permission.POST_NOTIFICATIONS",
  "android.permission.USE_BIOMETRIC",
  "android.permission.USE_FINGERPRINT",
  "android.permission.VIBRATE",
  "android.permission.WAKE_LOCK",
  DYNAMIC_RECEIVER_PERMISSION,
]);
const EXPECTED_SIGNATURE_SCHEME_POLICY = Object.freeze({
  v1: false,
  v2: true,
  v3: false,
  "v3.1": false,
  v4: false,
});
const APPLICATION_COMPONENT_TAGS = new Set([
  "activity",
  "activity-alias",
  "provider",
  "receiver",
  "service",
]);
const COMPONENT_SECURITY_ATTRIBUTES = Object.freeze([
  "android:allowEmbedded",
  "android:allowTaskReparenting",
  "android:allowUntrustedActivityEmbedding",
  "android:alwaysRetainTaskState",
  "android:authorities",
  "android:autoRemoveFromRecents",
  "android:directBootAware",
  "android:documentLaunchMode",
  "android:enabled",
  "android:excludeFromRecents",
  "android:exported",
  "android:externalService",
  "android:finishOnTaskLaunch",
  "android:forceUriPermissions",
  "android:foregroundServiceType",
  "android:grantUriPermissions",
  "android:immersive",
  "android:inheritShowWhenLocked",
  "android:isolatedProcess",
  "android:launchMode",
  "android:lockTaskMode",
  "android:maxRecents",
  "android:multiprocess",
  "android:noHistory",
  "android:permission",
  "android:persistableMode",
  "android:process",
  "android:readPermission",
  "android:relinquishTaskIdentity",
  "android:resizeableActivity",
  "android:screenOrientation",
  "android:showForAllUsers",
  "android:showWhenLocked",
  "android:singleUser",
  "android:stateNotNeeded",
  "android:stopWithTask",
  "android:supportsPictureInPicture",
  "android:syncable",
  "android:taskAffinity",
  "android:turnScreenOn",
  "android:useAppZygote",
  "android:visibleToInstantApps",
  "android:writePermission",
]);
const EXPECTED_COMPONENTS = Object.freeze([
  Object.freeze({
    type: "activity",
    name: MAIN_ACTIVITY_CLASS,
    securityAttributes: Object.freeze({
      "android:exported": "true",
      "android:launchMode": "2",
      "android:screenOrientation": "1",
    }),
  }),
  Object.freeze({
    type: "activity",
    name: RECOVERY_ACTIVITY_CLASS,
    securityAttributes: Object.freeze({
      "android:excludeFromRecents": "true",
      "android:exported": "false",
      "android:noHistory": "false",
      "android:stateNotNeeded": "true",
    }),
  }),
  Object.freeze({
    type: "service",
    name: PUSH_SERVICE_CLASS,
    securityAttributes: Object.freeze({ "android:exported": "false" }),
  }),
  Object.freeze({
    type: "provider",
    name: FILE_SYSTEM_PROVIDER_CLASS,
    securityAttributes: Object.freeze({
      "android:authorities": `${EXPECTED_APPLICATION_ID}.FileSystemFileProvider`,
      "android:exported": "false",
      "android:grantUriPermissions": "true",
    }),
  }),
  Object.freeze({
    type: "provider",
    name: INITIALIZATION_PROVIDER_CLASS,
    securityAttributes: Object.freeze({
      "android:authorities": `${EXPECTED_APPLICATION_ID}.androidx-startup`,
      "android:exported": "false",
    }),
  }),
  Object.freeze({
    type: "receiver",
    name: PROFILE_INSTALL_RECEIVER_CLASS,
    securityAttributes: Object.freeze({
      "android:directBootAware": "false",
      "android:enabled": "true",
      "android:exported": "true",
      "android:permission": "android.permission.DUMP",
    }),
  }),
]);
const EXPECTED_COMPONENT_EVIDENCE = Object.freeze(EXPECTED_COMPONENTS.map(
  (component) => Object.freeze({
    type: component.type,
    name: component.name,
    enabled: component.securityAttributes["android:enabled"] !== "false",
    exported: component.securityAttributes["android:exported"] === "true",
    permission: component.securityAttributes["android:permission"] ?? null,
    authorities: component.securityAttributes["android:authorities"] ?? null,
    grantUriPermissions: component.securityAttributes["android:grantUriPermissions"] === "true",
  }),
));
const FORBIDDEN_BACKUP_OVERRIDE_ATTRIBUTES = Object.freeze([
  "android:backupAgent",
  "android:backupInForeground",
  "android:fullBackupOnly",
  "android:hasFragileUserData",
  "android:killAfterRestore",
  "android:restoreAnyVersion",
]);
const FORBIDDEN_APPLICATION_SECURITY_ATTRIBUTES = Object.freeze([
  "android:allowTaskReparenting",
  "android:directBootAware",
  "android:enabled",
  "android:manageSpaceActivity",
  "android:permission",
  "android:persistent",
  "android:process",
  "android:requestLegacyExternalStorage",
  "android:resizeableActivity",
  "android:taskAffinity",
  "android:testOnly",
]);
const FORBIDDEN_MANIFEST_IDENTITY_ATTRIBUTES = Object.freeze([
  "android:sharedUserId",
  "android:sharedUserLabel",
  "android:sharedUserMaxSdkVersion",
  "android:targetSandboxVersion",
]);
const REQUIRED_ASSET = "assets/index.android.bundle";
const MAX_APK_BYTES = 1024 * 1024 * 1024;
const MAX_SIGNATURE_OUTPUT_BYTES = 256 * 1024;
const MAX_SMALL_OUTPUT_BYTES = 8 * 1024;
const MAX_PERMISSIONS_OUTPUT_BYTES = 64 * 1024;
const MAX_MANIFEST_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_FILE_LIST_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_RESOURCE_TABLE_OUTPUT_BYTES = 32 * 1024 * 1024;
const MAX_DATA_EXTRACTION_RULES_OUTPUT_BYTES = 256 * 1024;
const MAX_STDERR_BYTES = 256 * 1024;
const TOOL_TIMEOUT_MS = 60_000;
const TESTER_VERSION_NAME_PATTERN = /^[0-9]+(?:\.[0-9]+){2}-tester(?:\.[0-9A-Za-z][0-9A-Za-z.-]{0,31})?$/;

const ARGUMENTS = new Set([
  "--android-sdk",
  "--aapt2-path",
  "--apkanalyzer-path",
  "--apk",
  "--apksigner-path",
  "--evidence-out",
  "--expected-cert-sha256",
  "--expected-source-commit",
  "--expected-version-code",
  "--expected-version-name",
  "--forbidden-cert-sha256",
]);

const REQUIRED_ARGUMENTS = Object.freeze([
  "--apk",
  "--expected-cert-sha256",
  "--forbidden-cert-sha256",
  "--expected-version-code",
  "--expected-version-name",
  "--expected-source-commit",
  "--evidence-out",
]);

export class VerificationError extends Error {
  constructor(code) {
    super(code);
    this.name = "VerificationError";
    this.code = code;
  }
}

function fail(code) {
  throw new VerificationError(code);
}

function assertSafeScalar(value, code, maxBytes = 4096) {
  if (typeof value !== "string" || value.length === 0) fail(code);
  if (Buffer.byteLength(value, "utf8") > maxBytes) fail(code);
  for (const character of value) {
    const point = character.codePointAt(0);
    if (point === 0 || point === 0x7f || point < 0x20) fail(code);
  }
}

function normalizePathArgument(value, code) {
  assertSafeScalar(value, code);
  if (value === "." || value === "..") fail(code);
  return resolve(value);
}

function assertTesterVersionName(value, code) {
  assertSafeScalar(value, code, 64);
  if (!TESTER_VERSION_NAME_PATTERN.test(value)) fail(code);
}

export function parseArguments(argv) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.length % 2 !== 0) {
    fail("ARGS_SHAPE");
  }

  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!ARGUMENTS.has(name)) fail("ARGS_UNKNOWN");
    if (values.has(name)) fail("ARGS_DUPLICATE");
    assertSafeScalar(value, "ARGS_VALUE");
    values.set(name, value);
  }

  for (const name of REQUIRED_ARGUMENTS) {
    if (!values.has(name)) fail("ARGS_REQUIRED");
  }

  const sdk = values.get("--android-sdk");
  const aapt2 = values.get("--aapt2-path");
  const apksigner = values.get("--apksigner-path");
  const apkanalyzer = values.get("--apkanalyzer-path");
  if (sdk && (aapt2 || apksigner || apkanalyzer)) fail("ARGS_TOOL_MODE");
  if (!sdk && !(aapt2 && apksigner && apkanalyzer)) fail("ARGS_TOOL_MODE");

  const certificateSha256 = values.get("--expected-cert-sha256");
  if (!/^[0-9a-f]{64}$/.test(certificateSha256)) fail("ARGS_CERT_SHA256");
  const forbiddenCertificateSha256 = values.get("--forbidden-cert-sha256");
  if (!/^[0-9a-f]{64}$/.test(forbiddenCertificateSha256)) {
    fail("ARGS_FORBIDDEN_CERT_SHA256");
  }
  if (certificateSha256 === forbiddenCertificateSha256) fail("ARGS_CERT_NOT_DISTINCT");

  const sourceCommit = values.get("--expected-source-commit");
  if (!/^[0-9a-f]{40}$/.test(sourceCommit)) fail("ARGS_SOURCE_COMMIT");

  const versionCodeText = values.get("--expected-version-code");
  if (!/^[1-9][0-9]{0,9}$/.test(versionCodeText)) fail("ARGS_VERSION_CODE");
  const versionCode = Number(versionCodeText);
  if (!Number.isSafeInteger(versionCode) || versionCode > 2_100_000_000) {
    fail("ARGS_VERSION_CODE");
  }

  const versionName = values.get("--expected-version-name");
  assertTesterVersionName(versionName, "ARGS_VERSION_NAME");

  const apkPath = normalizePathArgument(values.get("--apk"), "ARGS_APK_PATH");
  const evidencePath = normalizePathArgument(
    values.get("--evidence-out"),
    "ARGS_EVIDENCE_PATH",
  );
  if (apkPath === evidencePath) fail("ARGS_PATH_COLLISION");

  return Object.freeze({
    apkPath,
    evidencePath,
    certificateSha256,
    forbiddenCertificateSha256,
    sourceCommit,
    versionCode,
    versionName,
    toolMode: sdk ? "android-sdk" : "explicit-paths",
    androidSdkPath: sdk ? normalizePathArgument(sdk, "ARGS_SDK_PATH") : null,
    aapt2Path: aapt2 ? normalizePathArgument(aapt2, "ARGS_AAPT2_PATH") : null,
    apksignerPath: apksigner
      ? normalizePathArgument(apksigner, "ARGS_APKSIGNER_PATH")
      : null,
    apkanalyzerPath: apkanalyzer
      ? normalizePathArgument(apkanalyzer, "ARGS_APKANALYZER_PATH")
      : null,
  });
}

function validateDecodedToolText(text, code) {
  for (const character of text) {
    const point = character.codePointAt(0);
    if (point === 0 || point === 0x7f || (point < 0x20 && point !== 0x0a && point !== 0x0d)) {
      fail(code);
    }
  }
  return text.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
}

function assertBoundedOutputString(output, maximumBytes, code) {
  if (typeof output !== "string" || Buffer.byteLength(output, "utf8") > maximumBytes) {
    fail(code);
  }
}

function decodeToolBuffer(buffer, code) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    fail(code);
  }
  return validateDecodedToolText(text, code);
}

function exactOutputLines(output, code) {
  const text = validateDecodedToolText(output, code);
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.some((line) => line.length === 0 || line.length > 16_384)) fail(code);
  return lines;
}

export function parseApkSignerOutput(
  output,
  expectedCertificateSha256,
  forbiddenCertificateSha256,
) {
  if (!/^[0-9a-f]{64}$/.test(expectedCertificateSha256)) fail("SIGNER_EXPECTED_DIGEST");
  if (!/^[0-9a-f]{64}$/.test(forbiddenCertificateSha256)) {
    fail("SIGNER_FORBIDDEN_DIGEST");
  }
  if (expectedCertificateSha256 === forbiddenCertificateSha256) {
    fail("SIGNER_CERT_NOT_DISTINCT");
  }
  assertBoundedOutputString(output, MAX_SIGNATURE_OUTPUT_BYTES, "SIGNER_OUTPUT_SIZE");
  const lines = exactOutputLines(output, "SIGNER_OUTPUT_FORMAT");
  if (lines.filter((line) => line === "Verifies").length !== 1) {
    fail("SIGNER_NOT_VERIFIED");
  }
  if (lines.some((line) => /^(?:WARNING|ERROR):|DOES NOT VERIFY/.test(line))) {
    fail("SIGNER_DIAGNOSTIC");
  }

  const signerCounts = lines
    .map((line) => /^Number of signers: ([0-9]+)$/.exec(line))
    .filter(Boolean);
  if (signerCounts.length !== 1 || signerCounts[0][1] !== "1") {
    fail("SIGNER_COUNT");
  }

  const schemePattern = /^Verified using v([0-9]+(?:\.[0-9]+)?) scheme(?: \([^\r\n)]{1,120}\))?: (true|false)$/;
  const schemeLines = [];
  for (const line of lines) {
    if (!line.startsWith("Verified using v")) continue;
    const match = schemePattern.exec(line);
    if (!match) fail("SIGNER_SCHEME");
    schemeLines.push(match);
  }
  const actualSchemePolicy = Object.fromEntries(
    schemeLines.map((match) => [`v${match[1]}`, match[2] === "true"]),
  );
  if (
    schemeLines.length !== Object.keys(EXPECTED_SIGNATURE_SCHEME_POLICY).length
    || new Set(schemeLines.map((match) => match[1])).size !== schemeLines.length
    || Object.keys(actualSchemePolicy).some(
      (scheme) => !(scheme in EXPECTED_SIGNATURE_SCHEME_POLICY),
    )
    || Object.entries(EXPECTED_SIGNATURE_SCHEME_POLICY).some(
      ([scheme, expected]) => actualSchemePolicy[scheme] !== expected,
    )
  ) {
    fail("SIGNER_SCHEME");
  }

  const digests = [];
  for (const line of lines) {
    const match = /^Signer #([0-9]+) certificate SHA-256 digest: ([0-9A-Fa-f:]+)$/.exec(line);
    if (!match) {
      if (line.includes("certificate SHA-256 digest:")) fail("SIGNER_DIGEST_FORMAT");
      continue;
    }
    const digest = match[2].replaceAll(":", "").toLowerCase();
    if (match[1] !== "1" || !/^[0-9a-f]{64}$/.test(digest)) {
      fail("SIGNER_DIGEST_FORMAT");
    }
    digests.push(digest);
  }
  if (digests.length !== 1) fail("SIGNER_DIGEST_COUNT");
  if (digests[0] === forbiddenCertificateSha256) fail("SIGNER_FORBIDDEN_CERTIFICATE");
  if (digests[0] !== expectedCertificateSha256) fail("SIGNER_DIGEST_MISMATCH");

  return Object.freeze({
    count: 1,
    certificateSha256: digests[0],
    signatureSchemePolicy: EXPECTED_SIGNATURE_SCHEME_POLICY,
  });
}

export function parseSingleLineOutput(output, code = "TOOL_SINGLE_LINE") {
  assertBoundedOutputString(output, MAX_SMALL_OUTPUT_BYTES, code);
  const text = validateDecodedToolText(output, code);
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.length !== 1 || lines[0].length === 0 || lines[0].length > 4096) fail(code);
  return lines[0];
}

export function verifyTesterSdkVersions(minSdkOutput, targetSdkOutput) {
  const minSdk = parseSingleLineOutput(minSdkOutput, "MIN_SDK_OUTPUT");
  const targetSdk = parseSingleLineOutput(targetSdkOutput, "TARGET_SDK_OUTPUT");
  if (minSdk !== String(EXPECTED_MIN_SDK_VERSION)) fail("MIN_SDK_MISMATCH");
  if (targetSdk !== String(EXPECTED_TARGET_SDK_VERSION)) fail("TARGET_SDK_MISMATCH");
  return Object.freeze({
    minSdkVersion: EXPECTED_MIN_SDK_VERSION,
    targetSdkVersion: EXPECTED_TARGET_SDK_VERSION,
  });
}

export function verifyTesterPermissions(output) {
  assertBoundedOutputString(output, MAX_PERMISSIONS_OUTPUT_BYTES, "PERMISSIONS_OUTPUT_SIZE");
  const permissions = exactOutputLines(output, "PERMISSIONS_OUTPUT_FORMAT");
  if (new Set(permissions).size !== permissions.length) fail("PERMISSIONS_DUPLICATE");
  if (!exactStringSet(permissions, EXPECTED_PERMISSIONS)) fail("PERMISSIONS_MISMATCH");
  return Object.freeze([...EXPECTED_PERMISSIONS]);
}

function decodeXmlAttribute(value) {
  if (value.replace(/&(amp|quot|apos|lt|gt);/g, "").includes("&")) {
    fail("MANIFEST_XML_ENTITY");
  }
  const decoded = value.replace(/&(amp|quot|apos|lt|gt);/g, (_, entity) => ({
    amp: "&",
    apos: "'",
    gt: ">",
    lt: "<",
    quot: '"',
  })[entity]);
  return decoded;
}

function parseXmlStartTag(rawTag) {
  let content = rawTag;
  let selfClosing = false;
  if (/\/\s*$/.test(content)) {
    selfClosing = true;
    content = content.replace(/\/\s*$/, "");
  }

  const nameMatch = /^([A-Za-z_][A-Za-z0-9_.:-]*)/.exec(content);
  if (!nameMatch) fail("MANIFEST_XML_TAG");
  const name = nameMatch[1];
  let index = name.length;
  const attributes = new Map();
  while (index < content.length) {
    const whitespace = /^[ \n\r\t]+/.exec(content.slice(index));
    if (!whitespace) fail("MANIFEST_XML_ATTRIBUTE");
    index += whitespace[0].length;
    if (index === content.length) break;

    const attributeMatch = /^([A-Za-z_][A-Za-z0-9_.:-]*)/.exec(content.slice(index));
    if (!attributeMatch) fail("MANIFEST_XML_ATTRIBUTE");
    const attributeName = attributeMatch[1];
    if (attributes.has(attributeName)) fail("MANIFEST_XML_DUPLICATE_ATTRIBUTE");
    index += attributeName.length;
    const beforeEquals = /^[ \n\r\t]*/.exec(content.slice(index))[0];
    index += beforeEquals.length;
    if (content[index] !== "=") fail("MANIFEST_XML_ATTRIBUTE");
    index += 1;
    const afterEquals = /^[ \n\r\t]*/.exec(content.slice(index))[0];
    index += afterEquals.length;
    const quote = content[index];
    if (quote !== '"' && quote !== "'") fail("MANIFEST_XML_ATTRIBUTE");
    index += 1;
    const closingQuote = content.indexOf(quote, index);
    if (closingQuote < 0) fail("MANIFEST_XML_ATTRIBUTE");
    const rawValue = content.slice(index, closingQuote);
    if (rawValue.includes("<") || rawValue.includes(">")) fail("MANIFEST_XML_ATTRIBUTE");
    attributes.set(attributeName, decodeXmlAttribute(rawValue));
    index = closingQuote + 1;
  }
  return { name, attributes, selfClosing };
}

export function parseManifestXml(output) {
  assertBoundedOutputString(output, MAX_MANIFEST_OUTPUT_BYTES, "MANIFEST_OUTPUT_SIZE");
  let xml = validateDecodedToolText(output, "MANIFEST_OUTPUT_FORMAT");
  const declaration = '<?xml version="1.0" encoding="utf-8"?>';
  if (xml.startsWith(declaration)) xml = xml.slice(declaration.length);
  if (xml.includes("<!") || xml.includes("<?")) fail("MANIFEST_XML_DECLARATION");

  const stack = [];
  let cursor = 0;
  let manifestAttributes = null;
  let applicationAttributes = null;
  const metadata = new Map();
  const requestedPermissions = [];
  const permissionDeclarations = [];
  const applicationComponents = [];
  const providerGrantPolicyTags = [];
  let profileableCount = 0;
  let instrumentationCount = 0;
  let mainActivityCount = 0;
  let mainActivityAttributes = null;
  let recoveryActivityCount = 0;
  let recoveryActivityAttributes = null;
  const mainActivityIntentFilters = [];
  const applicationIntentData = [];
  const tagPattern = /<([^<>]+)>/g;
  let match;
  while ((match = tagPattern.exec(xml)) !== null) {
    if (!/^\s*$/.test(xml.slice(cursor, match.index))) fail("MANIFEST_XML_TEXT");
    cursor = tagPattern.lastIndex;
    const rawTag = match[1];
    if (rawTag.startsWith("/")) {
      const closing = rawTag.slice(1).trim();
      if (!/^[A-Za-z_][A-Za-z0-9_.:-]*$/.test(closing)) fail("MANIFEST_XML_CLOSE");
      if (stack.pop()?.name !== closing) fail("MANIFEST_XML_NESTING");
      continue;
    }

    const tag = parseXmlStartTag(rawTag);
    const parentNode = stack.at(-1) ?? null;
    const parent = parentNode?.name ?? null;
    const node = {
      name: tag.name,
      insideApplication: tag.name === "application" || Boolean(parentNode?.insideApplication),
      isMainActivity: false,
      componentType: null,
      intentFilter: null,
    };
    if (tag.name === "manifest") {
      if (manifestAttributes || parent !== null) fail("MANIFEST_ROOT");
      manifestAttributes = tag.attributes;
    } else if (tag.name === "application") {
      if (applicationAttributes || parent !== "manifest") fail("MANIFEST_APPLICATION_COUNT");
      applicationAttributes = tag.attributes;
    } else if (tag.name === "instrumentation" && parent === "manifest") {
      instrumentationCount += 1;
    } else if (tag.name === "profileable" && parent === "application") {
      profileableCount += 1;
    } else if (tag.name.startsWith("uses-permission") && parent === "manifest") {
      requestedPermissions.push({ tagName: tag.name, attributes: tag.attributes });
    } else if (
      (tag.name === "permission"
        || tag.name === "permission-group"
        || tag.name === "permission-tree")
      && parent === "manifest"
    ) {
      permissionDeclarations.push({ tagName: tag.name, attributes: tag.attributes });
    } else if (tag.name === "meta-data" && parent === "application") {
      const metadataName = tag.attributes.get("android:name");
      if (metadataName) {
        if (metadata.has(metadataName)) fail("MANIFEST_METADATA_DUPLICATE");
        if (tag.attributes.has("android:resource") && tag.attributes.has("android:value")) {
          fail("MANIFEST_METADATA_AMBIGUOUS");
        }
        metadata.set(metadataName, tag.attributes.get("android:value"));
      }
    } else if (APPLICATION_COMPONENT_TAGS.has(tag.name) && parent === "application") {
      const componentName = tag.attributes.get("android:name");
      node.componentType = tag.name;
      applicationComponents.push({
        type: tag.name,
        name: componentName,
        attributes: tag.attributes,
      });
      if (tag.name === "activity") {
        node.isMainActivity = componentName === MAIN_ACTIVITY_CLASS;
        if (node.isMainActivity) {
          mainActivityCount += 1;
          mainActivityAttributes = tag.attributes;
        }
        if (componentName === RECOVERY_ACTIVITY_CLASS) {
          recoveryActivityCount += 1;
          if (recoveryActivityCount > 1) fail("MANIFEST_RECOVERY_ACTIVITY_COUNT");
          recoveryActivityAttributes = tag.attributes;
        }
      }
    } else if (
      (tag.name === "grant-uri-permission" || tag.name === "path-permission")
      && parentNode?.componentType === "provider"
    ) {
      providerGrantPolicyTags.push(tag.name);
    } else if (tag.name === "intent-filter" && parentNode?.insideApplication) {
      const intentFilter = {
        attributes: tag.attributes,
        actions: [],
        categories: [],
        data: [],
        invalidChildren: false,
        isMainActivity: Boolean(parentNode?.isMainActivity),
      };
      node.intentFilter = intentFilter;
      if (intentFilter.isMainActivity) mainActivityIntentFilters.push(intentFilter);
    } else if (tag.name === "action" && parentNode?.intentFilter) {
      if (tag.attributes.size !== 1 || !tag.attributes.has("android:name")) {
        parentNode.intentFilter.invalidChildren = true;
      }
      parentNode.intentFilter.actions.push(tag.attributes.get("android:name"));
    } else if (tag.name === "category" && parentNode?.intentFilter) {
      if (tag.attributes.size !== 1 || !tag.attributes.has("android:name")) {
        parentNode.intentFilter.invalidChildren = true;
      }
      parentNode.intentFilter.categories.push(tag.attributes.get("android:name"));
    } else if (tag.name === "data" && node.insideApplication) {
      if (parentNode?.intentFilter) {
        parentNode.intentFilter.data.push(tag.attributes);
      }
      applicationIntentData.push({
        attributes: tag.attributes,
        isMainActivity: Boolean(parentNode?.intentFilter?.isMainActivity),
      });
    } else if (parentNode?.intentFilter) {
      parentNode.intentFilter.invalidChildren = true;
    }

    if (!tag.selfClosing) stack.push(node);
  }
  if (!/^\s*$/.test(xml.slice(cursor))) fail("MANIFEST_XML_TEXT");
  if (stack.length !== 0) fail("MANIFEST_XML_NESTING");
  if (!manifestAttributes) fail("MANIFEST_ROOT");
  if (!applicationAttributes) fail("MANIFEST_APPLICATION_COUNT");

  return {
    manifestAttributes,
    applicationAttributes,
    metadata,
    requestedPermissions,
    permissionDeclarations,
    applicationComponents,
    providerGrantPolicyTags,
    profileableCount,
    instrumentationCount,
    mainActivityCount,
    mainActivityAttributes,
    recoveryActivityCount,
    recoveryActivityAttributes,
    mainActivityIntentFilters,
    applicationIntentData,
  };
}

function assertTesterComponentManifest(parsed) {
  if (!Array.isArray(parsed.applicationComponents)) fail("MANIFEST_COMPONENT_INVENTORY");
  if (
    !Array.isArray(parsed.providerGrantPolicyTags)
    || parsed.providerGrantPolicyTags.length !== 0
  ) {
    fail("MANIFEST_PROVIDER_GRANT_POLICY");
  }

  const actualByKey = new Map();
  const names = new Set();
  for (const component of parsed.applicationComponents) {
    if (component?.type === "activity-alias") fail("MANIFEST_COMPONENT_TYPE");
    if (
      !APPLICATION_COMPONENT_TAGS.has(component?.type)
      || component.type === "activity-alias"
      || typeof component.name !== "string"
      || component.name.length === 0
      || !(component.attributes instanceof Map)
    ) {
      fail("MANIFEST_COMPONENT_INVENTORY");
    }
    const key = `${component.type}\0${component.name}`;
    if (actualByKey.has(key) || names.has(component.name)) {
      fail("MANIFEST_COMPONENT_DUPLICATE");
    }
    actualByKey.set(key, component);
    names.add(component.name);
  }
  if (actualByKey.size !== EXPECTED_COMPONENTS.length) {
    fail("MANIFEST_COMPONENT_INVENTORY");
  }

  for (const expected of EXPECTED_COMPONENTS) {
    const component = actualByKey.get(`${expected.type}\0${expected.name}`);
    if (!component) fail("MANIFEST_COMPONENT_INVENTORY");
    for (const attributeName of COMPONENT_SECURITY_ATTRIBUTES) {
      if (Object.hasOwn(expected.securityAttributes, attributeName)) {
        if (component.attributes.get(attributeName) !== expected.securityAttributes[attributeName]) {
          fail("MANIFEST_COMPONENT_SECURITY");
        }
      } else if (component.attributes.has(attributeName)) {
        fail("MANIFEST_COMPONENT_SECURITY");
      }
    }
  }

  return EXPECTED_COMPONENT_EVIDENCE;
}

function exactStringSet(values, expected) {
  return (
    values.length === expected.length
    && new Set(values).size === values.length
    && expected.every((value) => values.includes(value))
  );
}

function assertTesterPermissionManifest(parsed) {
  if (!Array.isArray(parsed.requestedPermissions)) fail("MANIFEST_PERMISSIONS");
  const permissionNames = [];
  for (const permission of parsed.requestedPermissions) {
    if (
      permission?.tagName !== "uses-permission"
      || !(permission.attributes instanceof Map)
      || permission.attributes.size !== 1
    ) {
      fail("MANIFEST_PERMISSIONS");
    }
    permissionNames.push(permission.attributes.get("android:name"));
  }
  if (new Set(permissionNames).size !== permissionNames.length) {
    fail("MANIFEST_PERMISSION_DUPLICATE");
  }
  if (!exactStringSet(permissionNames, EXPECTED_PERMISSIONS)) {
    fail("MANIFEST_PERMISSIONS");
  }

  if (
    !Array.isArray(parsed.permissionDeclarations)
    || parsed.permissionDeclarations.length !== 1
  ) {
    fail("MANIFEST_PERMISSION_DECLARATION");
  }
  const declaration = parsed.permissionDeclarations[0];
  if (
    declaration?.tagName !== "permission"
    || !(declaration.attributes instanceof Map)
    || declaration.attributes.size !== 2
    || declaration.attributes.get("android:name") !== DYNAMIC_RECEIVER_PERMISSION
    || declaration.attributes.get("android:protectionLevel") !== "0x2"
  ) {
    fail("MANIFEST_PERMISSION_DECLARATION");
  }
}

function assertTesterEnrollmentHandlers(parsed) {
  if (parsed.mainActivityCount !== 1) fail("MANIFEST_MAIN_ACTIVITY");
  if (parsed.mainActivityIntentFilters.length !== 3) {
    fail("MANIFEST_MAIN_INTENT_FILTERS");
  }

  const launcherFilters = parsed.mainActivityIntentFilters.filter((filter) => (
    filter.data.length === 0
    && filter.actions.includes(MAIN_ACTION)
  ));
  if (launcherFilters.length !== 1) fail("MANIFEST_MAIN_INTENT_FILTERS");
  const launcherFilter = launcherFilters[0];
  if (
    launcherFilter.attributes.size !== 0
    || launcherFilter.invalidChildren
    || !exactStringSet(launcherFilter.actions, [MAIN_ACTION])
    || !exactStringSet(launcherFilter.categories, [LAUNCHER_CATEGORY])
  ) {
    fail("MANIFEST_MAIN_INTENT_FILTERS");
  }

  for (const datum of parsed.applicationIntentData) {
    const scheme = datum.attributes.get("android:scheme")?.toLowerCase();
    const host = datum.attributes.get("android:host")?.toLowerCase();
    if (scheme === "veil" || host === "veil.erez.pro") {
      fail("MANIFEST_PRODUCTION_HANDLER");
    }
    if ((scheme === "veil-tester" || host === "tester.invalid") && !datum.isMainActivity) {
      fail("MANIFEST_TESTER_HANDLER_SCOPE");
    }
  }

  const allMainData = parsed.mainActivityIntentFilters.flatMap((filter) => filter.data);
  if (allMainData.filter((data) => data.get("android:scheme") === "veil-tester").length !== 1) {
    fail("MANIFEST_TESTER_SCHEME_HANDLER");
  }
  if (allMainData.filter((data) => data.get("android:host") === "tester.invalid").length !== 1) {
    fail("MANIFEST_TESTER_HTTPS_HANDLER");
  }

  const customFilters = parsed.mainActivityIntentFilters.filter((filter) => (
    filter.data.length === 1
    && filter.data[0].get("android:scheme") === "veil-tester"
  ));
  if (customFilters.length !== 1) fail("MANIFEST_TESTER_SCHEME_HANDLER");
  const customFilter = customFilters[0];
  const customData = customFilter.data[0];
  if (
    customData.size !== 1
    || customFilter.invalidChildren
    || customFilter.attributes.size !== 0
    || customData.has("android:host")
    || customData.has("android:path")
    || customData.has("android:pathPrefix")
    || !exactStringSet(customFilter.actions, [VIEW_ACTION])
    || !exactStringSet(customFilter.categories, [DEFAULT_CATEGORY, BROWSABLE_CATEGORY])
  ) {
    fail("MANIFEST_TESTER_SCHEME_HANDLER");
  }

  const httpsFilters = parsed.mainActivityIntentFilters.filter((filter) => (
    filter.data.length === 1
    && filter.data[0].get("android:scheme") === "https"
    && filter.data[0].get("android:host") === "tester.invalid"
  ));
  if (httpsFilters.length !== 1) fail("MANIFEST_TESTER_HTTPS_HANDLER");
  const httpsFilter = httpsFilters[0];
  const httpsData = httpsFilter.data[0];
  if (
    httpsData.size !== 3
    || httpsFilter.invalidChildren
    || httpsFilter.attributes.size !== 1
    || httpsData.get("android:path") !== "/enroll"
    || httpsData.has("android:pathPrefix")
    || httpsFilter.attributes.get("android:autoVerify") !== "true"
    || !exactStringSet(httpsFilter.actions, [VIEW_ACTION])
    || !exactStringSet(httpsFilter.categories, [DEFAULT_CATEGORY, BROWSABLE_CATEGORY])
  ) {
    fail("MANIFEST_TESTER_HTTPS_HANDLER");
  }
}

export function assertTesterManifest(
  parsed,
  expectedSourceCommit,
  expectedVersionCode = null,
  expectedVersionName = null,
) {
  if (!/^[0-9a-f]{40}$/.test(expectedSourceCommit)) fail("MANIFEST_SOURCE_EXPECTED");
  if (parsed.manifestAttributes.get("package") !== EXPECTED_APPLICATION_ID) {
    fail("MANIFEST_PACKAGE");
  }
  if (FORBIDDEN_MANIFEST_IDENTITY_ATTRIBUTES.some(
    (attribute) => parsed.manifestAttributes.has(attribute),
  )) {
    fail("MANIFEST_IDENTITY_OVERRIDE");
  }
  if (FORBIDDEN_APPLICATION_SECURITY_ATTRIBUTES.some(
    (attribute) => parsed.applicationAttributes.has(attribute),
  )) {
    fail("MANIFEST_APPLICATION_SECURITY");
  }
  if (parsed.profileableCount !== 0) fail("MANIFEST_PROFILEABLE");
  if (parsed.instrumentationCount !== 0) fail("MANIFEST_INSTRUMENTATION");
  if (parsed.applicationAttributes.get("android:usesCleartextTraffic") !== "false") {
    fail("MANIFEST_CLEARTEXT");
  }
  if (parsed.applicationAttributes.get("android:allowBackup") !== "false") {
    fail("MANIFEST_ALLOW_BACKUP");
  }
  if (parsed.applicationAttributes.get("android:fullBackupContent") !== "false") {
    fail("MANIFEST_FULL_BACKUP");
  }
  if (FORBIDDEN_BACKUP_OVERRIDE_ATTRIBUTES.some(
    (attribute) => parsed.applicationAttributes.has(attribute),
  )) {
    fail("MANIFEST_BACKUP_OVERRIDE");
  }
  const dataExtractionRulesReference = parsed.applicationAttributes.get(
    "android:dataExtractionRules",
  );
  if (!/^@ref\/0x7f[0-9a-f]{6}$/.test(dataExtractionRulesReference)) {
    fail("MANIFEST_DATA_EXTRACTION_RULES_REFERENCE");
  }
  if (parsed.applicationAttributes.has("android:networkSecurityConfig")) {
    fail("MANIFEST_NETWORK_SECURITY_CONFIG");
  }
  if (
    parsed.mainActivityCount !== 1
    || parsed.mainActivityAttributes?.get("android:exported") !== "true"
  ) {
    fail("MANIFEST_MAIN_ACTIVITY_POLICY");
  }
  if (
    parsed.recoveryActivityCount !== 1
    || parsed.recoveryActivityAttributes?.get("android:exported") !== "false"
    || parsed.recoveryActivityAttributes?.get("android:excludeFromRecents") !== "true"
    || parsed.recoveryActivityAttributes?.get("android:stateNotNeeded") !== "true"
    || parsed.recoveryActivityAttributes?.get("android:noHistory") !== "false"
  ) {
    fail("MANIFEST_RECOVERY_ACTIVITY_POLICY");
  }
  assertTesterPermissionManifest(parsed);
  const iconReference = parsed.applicationAttributes.get("android:icon");
  const roundIconReference = parsed.applicationAttributes.get("android:roundIcon");
  if (
    !/^@ref\/0x7f[0-9a-f]{6}$/.test(iconReference)
    || roundIconReference !== iconReference
  ) {
    fail("MANIFEST_TESTER_ICON_REFERENCE");
  }
  const applicationLabelReference = parsed.applicationAttributes.get("android:label");
  const recoveryLabelReference = parsed.recoveryActivityAttributes?.get("android:label");
  if (
    !/^@ref\/0x7f[0-9a-f]{6}$/.test(applicationLabelReference)
    || !/^@ref\/0x7f[0-9a-f]{6}$/.test(recoveryLabelReference)
    || recoveryLabelReference === applicationLabelReference
    || parsed.mainActivityAttributes?.has("android:label")
  ) {
    fail("MANIFEST_TESTER_LABEL_REFERENCE");
  }
  const manifestDebuggable = parsed.applicationAttributes.get("android:debuggable");
  if (manifestDebuggable !== undefined && manifestDebuggable !== "false") {
    fail("MANIFEST_DEBUGGABLE");
  }
  if ((expectedVersionCode === null) !== (expectedVersionName === null)) {
    fail("MANIFEST_VERSION_EXPECTATION");
  }

  if (expectedVersionCode !== null) {
    if (
      !Number.isSafeInteger(expectedVersionCode)
      || parsed.manifestAttributes.get("android:versionCode") !== String(expectedVersionCode)
      || parsed.manifestAttributes.get("android:versionName") !== expectedVersionName
    ) {
      fail("MANIFEST_VERSION_MISMATCH");
    }
  }

  const expectedMetadata = new Map([
    ...Object.entries(EXPECTED_METADATA),
    ["io.veil.mobile.SOURCE_COMMIT", expectedSourceCommit],
  ]);
  for (const [name, expectedValue] of expectedMetadata) {
    if (!parsed.metadata.has(name)) fail("MANIFEST_METADATA_MISSING");
    if (parsed.metadata.get(name) !== expectedValue) fail("MANIFEST_METADATA_VALUE");
  }
  assertTesterEnrollmentHandlers(parsed);
  const components = assertTesterComponentManifest(parsed);

  return Object.freeze({
    allowBackup: false,
    dataExtractionRulesResource: EXPECTED_DATA_EXTRACTION_RULES_RESOURCE,
    fullBackupContent: false,
    hasBackupAgent: false,
    backupOverrideAttributesPresent: Object.freeze([]),
    hasNetworkSecurityConfig: false,
    iconResource: EXPECTED_TESTER_ICON_RESOURCE,
    roundIconResource: EXPECTED_TESTER_ICON_RESOURCE,
    applicationLabelResource: "@string/app_name",
    recoveryActivityLabelResource: "@string/recovery_activity_label",
    usesCleartextTraffic: false,
    activities: Object.freeze({
      main: Object.freeze({ exported: true }),
      recovery: Object.freeze({
        exported: false,
        excludeFromRecents: true,
        stateNotNeeded: true,
        noHistory: false,
      }),
    }),
    components,
    permissions: Object.freeze([...EXPECTED_PERMISSIONS]),
    signaturePermission: Object.freeze({
      name: DYNAMIC_RECEIVER_PERMISSION,
      protectionLevel: "signature",
    }),
    metadata: Object.freeze({
      ALLOW_READY_SCREEN_CAPTURE: "false",
      BUILD_CHANNEL: "tester",
      ENROLLMENT_HTTPS_HOST: "tester.invalid",
      ENROLLMENT_SCHEME: "veil-tester",
      EXPO_UPDATES_ENABLED: "false",
      SOURCE_COMMIT: expectedSourceCommit,
    }),
  });
}

export function verifyTesterResourceBindings(parsed, output) {
  const iconReference = parsed?.applicationAttributes?.get?.("android:icon");
  const roundIconReference = parsed?.applicationAttributes?.get?.("android:roundIcon");
  const applicationLabelReference = parsed?.applicationAttributes?.get?.("android:label");
  const recoveryLabelReference = parsed?.recoveryActivityAttributes?.get?.("android:label");
  const dataExtractionRulesReference = parsed?.applicationAttributes?.get?.(
    "android:dataExtractionRules",
  );
  const extractId = (reference) => /^@ref\/(0x7f[0-9a-f]{6})$/.exec(reference ?? "")?.[1];
  const iconId = extractId(iconReference);
  const applicationLabelId = extractId(applicationLabelReference);
  const recoveryLabelId = extractId(recoveryLabelReference);
  const dataExtractionRulesId = extractId(dataExtractionRulesReference);
  if (
    !iconId
    || roundIconReference !== iconReference
    || !applicationLabelId
    || !recoveryLabelId
    || !dataExtractionRulesId
    || new Set([
      iconId,
      applicationLabelId,
      recoveryLabelId,
      dataExtractionRulesId,
    ]).size !== 4
  ) {
    fail("RESOURCE_MANIFEST_REFERENCE");
  }

  const bindings = [
    {
      id: iconId,
      name: EXPECTED_TESTER_ICON_TABLE_NAME,
      idError: "AAPT2_ICON_ID_MAPPING",
      bindingError: "AAPT2_TESTER_ICON_BINDING",
    },
    {
      id: applicationLabelId,
      name: "string/app_name",
      idError: "AAPT2_APP_LABEL_ID_MAPPING",
      bindingError: "AAPT2_APP_LABEL_BINDING",
    },
    {
      id: recoveryLabelId,
      name: "string/recovery_activity_label",
      idError: "AAPT2_RECOVERY_LABEL_ID_MAPPING",
      bindingError: "AAPT2_RECOVERY_LABEL_BINDING",
    },
    {
      id: dataExtractionRulesId,
      name: EXPECTED_DATA_EXTRACTION_RULES_TABLE_NAME,
      idError: "AAPT2_DATA_EXTRACTION_RULES_ID_MAPPING",
      bindingError: "AAPT2_DATA_EXTRACTION_RULES_BINDING",
    },
  ];
  const manifestIds = new Set(bindings.map(({ id }) => id));
  const expectedNames = new Set(bindings.map(({ name }) => name));

  assertBoundedOutputString(
    output,
    MAX_RESOURCE_TABLE_OUTPUT_BYTES,
    "AAPT2_RESOURCE_OUTPUT_SIZE",
  );
  const text = validateDecodedToolText(output, "AAPT2_RESOURCE_OUTPUT_FORMAT");
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.length === 0 || lines.length > 1_000_000 || lines[0] !== "Binary APK") {
    fail("AAPT2_RESOURCE_OUTPUT_FORMAT");
  }
  if (
    lines.filter((line) => line === `Package name=${EXPECTED_APPLICATION_ID} id=7f`).length !== 1
  ) {
    fail("AAPT2_RESOURCE_PACKAGE");
  }

  const relevantResources = [];
  let current = null;
  for (const line of lines) {
    if (line.length > 32_768) fail("AAPT2_RESOURCE_OUTPUT_FORMAT");
    const resourceMatch = /^    resource (0x[0-9a-f]{8}) (\S+\/\S+)$/.exec(line);
    if (line.startsWith("    resource ") && !resourceMatch) {
      fail("AAPT2_RESOURCE_OUTPUT_FORMAT");
    }
    if (resourceMatch) {
      const [, id, name] = resourceMatch;
      current = (
        manifestIds.has(id)
        || expectedNames.has(name)
      ) ? { id, name, fileLines: [] } : null;
      if (current) relevantResources.push(current);
      continue;
    }
    if (current && line.includes("(file)")) current.fileLines.push(line);
  }

  let iconMapping;
  let dataExtractionRulesMapping;
  for (const binding of bindings) {
    const idMappings = relevantResources.filter(({ id }) => id === binding.id);
    if (idMappings.length !== 1) fail(binding.idError);
    if (
      binding.name === EXPECTED_TESTER_ICON_TABLE_NAME
      && idMappings[0].name === PRODUCTION_ICON_TABLE_NAME
    ) {
      fail("AAPT2_PRODUCTION_ICON_BINDING");
    }
    if (idMappings[0].name !== binding.name) fail(binding.bindingError);
    const nameMappings = relevantResources.filter(({ name }) => name === binding.name);
    if (nameMappings.length !== 1 || nameMappings[0].id !== binding.id) {
      fail(binding.bindingError);
    }
    if (binding.name === EXPECTED_TESTER_ICON_TABLE_NAME) iconMapping = nameMappings[0];
    if (binding.name === EXPECTED_DATA_EXTRACTION_RULES_TABLE_NAME) {
      dataExtractionRulesMapping = nameMappings[0];
    }
  }
  const expectedIconFileLine = `      () (file) ${EXPECTED_TESTER_ICON_FILE} type=XML`;
  if (
    iconMapping.fileLines.length !== 1
    || iconMapping.fileLines[0] !== expectedIconFileLine
  ) {
    fail("AAPT2_TESTER_ICON_FILE");
  }
  const expectedDataExtractionRulesFileLine = (
    `      () (file) ${EXPECTED_DATA_EXTRACTION_RULES_FILE} type=XML`
  );
  if (
    dataExtractionRulesMapping.fileLines.length !== 1
    || dataExtractionRulesMapping.fileLines[0] !== expectedDataExtractionRulesFileLine
  ) {
    fail("AAPT2_DATA_EXTRACTION_RULES_FILE");
  }

  return Object.freeze({
    iconResource: EXPECTED_TESTER_ICON_RESOURCE,
    roundIconResource: EXPECTED_TESTER_ICON_RESOURCE,
    applicationLabelResource: "@string/app_name",
    recoveryActivityLabelResource: "@string/recovery_activity_label",
    dataExtractionRulesResource: EXPECTED_DATA_EXTRACTION_RULES_RESOURCE,
  });
}

export function verifyTesterDataExtractionRules(output) {
  assertBoundedOutputString(
    output,
    MAX_DATA_EXTRACTION_RULES_OUTPUT_BYTES,
    "DATA_EXTRACTION_RULES_OUTPUT_SIZE",
  );
  const lines = exactOutputLines(output, "DATA_EXTRACTION_RULES_OUTPUT_FORMAT");
  let cursor = 0;
  const consume = (pattern) => {
    if (cursor >= lines.length || !pattern.test(lines[cursor])) {
      fail("DATA_EXTRACTION_RULES_POLICY");
    }
    cursor += 1;
  };
  const element = (indent, name) => new RegExp(
    `^${" ".repeat(indent)}E: ${name} \\(line=[1-9][0-9]*\\)$`,
  );
  const exclude = (domain) => {
    consume(element(8, "exclude"));
    consume(new RegExp(
      `^          A: domain="${domain}" \\(Raw: "${domain}"\\)$`,
    ));
    consume(/^          A: path="\." \(Raw: "\."\)$/);
  };

  consume(element(0, "data-extraction-rules"));
  consume(element(4, "cloud-backup"));
  consume(/^      A: disableIfNoEncryptionCapabilities=true$/);
  for (const domain of EXPECTED_BACKUP_EXCLUDED_DOMAINS) exclude(domain);
  consume(element(4, "device-transfer"));
  for (const domain of EXPECTED_BACKUP_EXCLUDED_DOMAINS) exclude(domain);
  if (cursor !== lines.length) fail("DATA_EXTRACTION_RULES_POLICY");

  return Object.freeze({
    dataExtractionRulesResource: EXPECTED_DATA_EXTRACTION_RULES_RESOURCE,
    cloudBackup: Object.freeze({
      disableIfNoEncryptionCapabilities: true,
      excludedDomains: Object.freeze([...EXPECTED_BACKUP_EXCLUDED_DOMAINS]),
    }),
    deviceTransfer: Object.freeze({
      excludedDomains: Object.freeze([...EXPECTED_BACKUP_EXCLUDED_DOMAINS]),
    }),
  });
}

export function verifyArchiveFileList(output) {
  assertBoundedOutputString(output, MAX_FILE_LIST_OUTPUT_BYTES, "FILES_OUTPUT_SIZE");
  const text = validateDecodedToolText(output, "FILES_OUTPUT_FORMAT");
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.length === 0 || lines.length > 200_000) fail("FILES_COUNT");

  if (lines[0] !== "/") fail("FILES_ROOT");
  const rawEntries = new Set();
  const files = new Set();
  for (const entry of lines) {
    if (
      entry.length === 0
      || entry.length > 4096
      || entry.includes("\\")
      || !entry.startsWith("/")
    ) {
      fail("FILES_ENTRY_FORMAT");
    }
    if (rawEntries.has(entry)) fail("FILES_DUPLICATE");
    rawEntries.add(entry);
    if (entry === "/") continue;

    const directory = entry.endsWith("/");
    const normalized = directory ? entry.slice(1, -1) : entry.slice(1);
    if (
      normalized.length === 0
      || normalized.split("/").some((segment) => segment === "" || segment === "." || segment === "..")
    ) {
      fail("FILES_ENTRY_FORMAT");
    }
    if (!directory) files.add(normalized);
  }

  if (!files.has(REQUIRED_ASSET)) fail("FILES_BUNDLE_MISSING");
  const veilFfiAbis = [];
  for (const entry of files) {
    if (!entry.endsWith("/libveil_ffi.so") && entry !== "libveil_ffi.so") continue;
    const match = /^lib\/([^/]+)\/libveil_ffi\.so$/.exec(entry);
    if (!match) fail("FILES_VEIL_FFI_PATH");
    veilFfiAbis.push(match[1]);
  }
  veilFfiAbis.sort();
  const expected = [...EXPECTED_ABIS].sort();
  if (veilFfiAbis.length !== expected.length || veilFfiAbis.some((abi, index) => abi !== expected[index])) {
    fail("FILES_VEIL_FFI_ABIS");
  }

  return Object.freeze({
    requiredAsset: REQUIRED_ASSET,
    veilFfiAbis: Object.freeze([...veilFfiAbis]),
  });
}

export function assertTesterBranding(values) {
  if (values === null || typeof values !== "object" || Array.isArray(values)) {
    fail("BRANDING_VALUES");
  }
  const expectedNames = Object.keys(EXPECTED_BRANDING_RESOURCES);
  const names = Object.keys(values);
  if (
    names.length !== expectedNames.length
    || names.some((name) => !Object.hasOwn(EXPECTED_BRANDING_RESOURCES, name))
  ) {
    fail("BRANDING_VALUES");
  }
  for (const [name, expectedValue] of Object.entries(EXPECTED_BRANDING_RESOURCES)) {
    if (values[name] !== expectedValue) fail("BRANDING_VALUE_MISMATCH");
  }
  return Object.freeze({ ...EXPECTED_BRANDING_RESOURCES });
}

function assertTesterResourceEvidence(resources) {
  if (
    resources === null
    || typeof resources !== "object"
    || Array.isArray(resources)
    || Object.keys(resources).length !== 5
    || resources.iconResource !== EXPECTED_TESTER_ICON_RESOURCE
    || resources.roundIconResource !== EXPECTED_TESTER_ICON_RESOURCE
    || resources.applicationLabelResource !== "@string/app_name"
    || resources.recoveryActivityLabelResource !== "@string/recovery_activity_label"
    || resources.dataExtractionRulesResource !== EXPECTED_DATA_EXTRACTION_RULES_RESOURCE
  ) {
    fail("EVIDENCE_TESTER_RESOURCES");
  }
  return Object.freeze({
    iconResource: EXPECTED_TESTER_ICON_RESOURCE,
    roundIconResource: EXPECTED_TESTER_ICON_RESOURCE,
    applicationLabelResource: "@string/app_name",
    recoveryActivityLabelResource: "@string/recovery_activity_label",
    dataExtractionRulesResource: EXPECTED_DATA_EXTRACTION_RULES_RESOURCE,
  });
}

function assertTesterBackupPolicyEvidence(policy) {
  const exactDomains = (value) => (
    Array.isArray(value)
    && value.length === EXPECTED_BACKUP_EXCLUDED_DOMAINS.length
    && value.every((domain, index) => domain === EXPECTED_BACKUP_EXCLUDED_DOMAINS[index])
  );
  if (
    policy === null
    || typeof policy !== "object"
    || Array.isArray(policy)
    || Object.keys(policy).length !== 3
    || policy.dataExtractionRulesResource !== EXPECTED_DATA_EXTRACTION_RULES_RESOURCE
    || policy.cloudBackup === null
    || typeof policy.cloudBackup !== "object"
    || Array.isArray(policy.cloudBackup)
    || Object.keys(policy.cloudBackup).length !== 2
    || policy.cloudBackup.disableIfNoEncryptionCapabilities !== true
    || !exactDomains(policy.cloudBackup.excludedDomains)
    || policy.deviceTransfer === null
    || typeof policy.deviceTransfer !== "object"
    || Array.isArray(policy.deviceTransfer)
    || Object.keys(policy.deviceTransfer).length !== 1
    || !exactDomains(policy.deviceTransfer.excludedDomains)
  ) {
    fail("EVIDENCE_BACKUP_POLICY");
  }
  return Object.freeze({
    dataExtractionRulesResource: EXPECTED_DATA_EXTRACTION_RULES_RESOURCE,
    cloudBackup: Object.freeze({
      disableIfNoEncryptionCapabilities: true,
      excludedDomains: Object.freeze([...EXPECTED_BACKUP_EXCLUDED_DOMAINS]),
    }),
    deviceTransfer: Object.freeze({
      excludedDomains: Object.freeze([...EXPECTED_BACKUP_EXCLUDED_DOMAINS]),
    }),
  });
}

function assertTesterSdkEvidence(sdkVersions) {
  if (
    sdkVersions === null
    || typeof sdkVersions !== "object"
    || Array.isArray(sdkVersions)
    || Object.keys(sdkVersions).length !== 2
    || sdkVersions.minSdkVersion !== EXPECTED_MIN_SDK_VERSION
    || sdkVersions.targetSdkVersion !== EXPECTED_TARGET_SDK_VERSION
  ) {
    fail("EVIDENCE_SDK_VERSIONS");
  }
  return Object.freeze({
    minSdkVersion: EXPECTED_MIN_SDK_VERSION,
    targetSdkVersion: EXPECTED_TARGET_SDK_VERSION,
  });
}

function assertTesterPermissionEvidence(permissions) {
  if (
    !Array.isArray(permissions)
    || !exactStringSet(permissions, EXPECTED_PERMISSIONS)
  ) {
    fail("EVIDENCE_PERMISSIONS");
  }
  return Object.freeze([...EXPECTED_PERMISSIONS]);
}

function assertTesterComponentEvidence(components) {
  if (!Array.isArray(components) || components.length !== EXPECTED_COMPONENT_EVIDENCE.length) {
    fail("EVIDENCE_COMPONENTS");
  }
  const expectedKeys = [
    "authorities",
    "enabled",
    "exported",
    "grantUriPermissions",
    "name",
    "permission",
    "type",
  ];
  const actualByKey = new Map();
  for (const component of components) {
    if (
      component === null
      || typeof component !== "object"
      || Array.isArray(component)
      || !exactStringSet(Object.keys(component), expectedKeys)
      || typeof component.type !== "string"
      || typeof component.name !== "string"
    ) {
      fail("EVIDENCE_COMPONENTS");
    }
    const key = `${component.type}\0${component.name}`;
    if (actualByKey.has(key)) fail("EVIDENCE_COMPONENTS");
    actualByKey.set(key, component);
  }
  for (const expected of EXPECTED_COMPONENT_EVIDENCE) {
    const actual = actualByKey.get(`${expected.type}\0${expected.name}`);
    if (
      !actual
      || actual.enabled !== expected.enabled
      || actual.exported !== expected.exported
      || actual.permission !== expected.permission
      || actual.authorities !== expected.authorities
      || actual.grantUriPermissions !== expected.grantUriPermissions
    ) {
      fail("EVIDENCE_COMPONENTS");
    }
  }
  return EXPECTED_COMPONENT_EVIDENCE;
}

function assertTesterBackupManifestEvidence(policy) {
  if (
    policy === null
    || typeof policy !== "object"
    || Array.isArray(policy)
    || !exactStringSet(
      Object.keys(policy),
      ["backupOverrideAttributesPresent", "hasBackupAgent"],
    )
    || policy.hasBackupAgent !== false
    || !Array.isArray(policy.backupOverrideAttributesPresent)
    || policy.backupOverrideAttributesPresent.length !== 0
  ) {
    fail("EVIDENCE_BACKUP_MANIFEST_POLICY");
  }
  return Object.freeze({
    hasBackupAgent: false,
    backupOverrideAttributesPresent: Object.freeze([]),
  });
}

export function buildEvidence({
  apkSha256,
  apkSizeBytes,
  certificateSha256,
  forbiddenCertificateSha256,
  signatureSchemePolicy,
  branding,
  resources,
  backupPolicy,
  sdkVersions,
  permissions,
  components,
  backupManifestPolicy,
  versionCode,
  versionName,
  sourceCommit,
  toolMode,
  verifiedAtUtc,
}) {
  if (!/^[0-9a-f]{64}$/.test(apkSha256)) fail("EVIDENCE_APK_SHA256");
  if (!Number.isSafeInteger(apkSizeBytes) || apkSizeBytes <= 0) fail("EVIDENCE_APK_SIZE");
  if (apkSizeBytes > MAX_APK_BYTES) fail("EVIDENCE_APK_SIZE");
  if (!/^[0-9a-f]{64}$/.test(certificateSha256)) fail("EVIDENCE_CERT_SHA256");
  if (!/^[0-9a-f]{64}$/.test(forbiddenCertificateSha256)) {
    fail("EVIDENCE_FORBIDDEN_CERT_SHA256");
  }
  if (certificateSha256 === forbiddenCertificateSha256) {
    fail("EVIDENCE_CERT_NOT_DISTINCT");
  }
  if (
    signatureSchemePolicy === null
    || typeof signatureSchemePolicy !== "object"
    || Array.isArray(signatureSchemePolicy)
    || Object.keys(signatureSchemePolicy).length !== Object.keys(EXPECTED_SIGNATURE_SCHEME_POLICY).length
    || Object.keys(signatureSchemePolicy).some(
      (scheme) => !(scheme in EXPECTED_SIGNATURE_SCHEME_POLICY),
    )
    || Object.entries(EXPECTED_SIGNATURE_SCHEME_POLICY).some(
      ([scheme, expected]) => signatureSchemePolicy[scheme] !== expected,
    )
  ) {
    fail("EVIDENCE_SIGNATURE_SCHEMES");
  }
  const verifiedBranding = assertTesterBranding(branding);
  const verifiedResources = assertTesterResourceEvidence(resources);
  const verifiedBackupPolicy = assertTesterBackupPolicyEvidence(backupPolicy);
  const verifiedSdkVersions = assertTesterSdkEvidence(sdkVersions);
  const verifiedPermissions = assertTesterPermissionEvidence(permissions);
  const verifiedComponents = assertTesterComponentEvidence(components);
  const verifiedBackupManifestPolicy = assertTesterBackupManifestEvidence(backupManifestPolicy);
  if (!/^[0-9a-f]{40}$/.test(sourceCommit)) fail("EVIDENCE_SOURCE_COMMIT");
  if (!Number.isSafeInteger(versionCode) || versionCode <= 0 || versionCode > 2_100_000_000) {
    fail("EVIDENCE_VERSION_CODE");
  }
  assertTesterVersionName(versionName, "EVIDENCE_VERSION_NAME");
  if (toolMode !== "android-sdk" && toolMode !== "explicit-paths") fail("EVIDENCE_TOOL_MODE");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(verifiedAtUtc)) {
    fail("EVIDENCE_TIMESTAMP");
  }

  return Object.freeze({
    schema: "veil.android-tester-apk-evidence.v1",
    verified: true,
    verifiedAtUtc,
    apk: Object.freeze({ sha256: apkSha256, sizeBytes: apkSizeBytes }),
    signer: Object.freeze({
      count: 1,
      certificateSha256,
      differentFromForbiddenCertificate: true,
      signatureSchemePolicy: EXPECTED_SIGNATURE_SCHEME_POLICY,
    }),
    branding: Object.freeze({
      iconResource: verifiedResources.iconResource,
      roundIconResource: verifiedResources.roundIconResource,
      applicationLabelResource: verifiedResources.applicationLabelResource,
      recoveryActivityLabelResource: verifiedResources.recoveryActivityLabelResource,
      ...verifiedBranding,
    }),
    manifest: Object.freeze({
      applicationId: EXPECTED_APPLICATION_ID,
      versionCode,
      versionName,
      minSdkVersion: verifiedSdkVersions.minSdkVersion,
      targetSdkVersion: verifiedSdkVersions.targetSdkVersion,
      debuggable: false,
      hasNetworkSecurityConfig: false,
      usesCleartextTraffic: false,
      backupAndTransferPolicy: Object.freeze({
        allowBackupManifestFlag: false,
        fullBackupContentManifestValue: false,
        backupAgentManifestValue: null,
        backupOverrideAttributesPresent: verifiedBackupManifestPolicy.backupOverrideAttributesPresent,
        dataExtractionRulesResource: verifiedResources.dataExtractionRulesResource,
        cloudBackup: verifiedBackupPolicy.cloudBackup,
        deviceTransfer: verifiedBackupPolicy.deviceTransfer,
      }),
      componentInventory: verifiedComponents,
      activities: Object.freeze({
        main: Object.freeze({ exported: true }),
        recovery: Object.freeze({
          exported: false,
          excludeFromRecents: true,
          stateNotNeeded: true,
          noHistory: false,
        }),
      }),
      permissionPolicy: Object.freeze({
        requested: verifiedPermissions,
        declaredSignaturePermission: Object.freeze({
          name: DYNAMIC_RECEIVER_PERMISSION,
          protectionLevel: "signature",
        }),
      }),
      metadata: Object.freeze({
        ALLOW_READY_SCREEN_CAPTURE: "false",
        BUILD_CHANNEL: "tester",
        ENROLLMENT_HTTPS_HOST: "tester.invalid",
        ENROLLMENT_SCHEME: "veil-tester",
        EXPO_UPDATES_ENABLED: "false",
        SOURCE_COMMIT: sourceCommit,
      }),
    }),
    contents: Object.freeze({
      requiredAssets: Object.freeze([REQUIRED_ASSET]),
      veilFfiAbis: Object.freeze([...EXPECTED_ABIS]),
    }),
    tools: Object.freeze({
      selection: toolMode,
      aapt2Source: toolMode === "android-sdk"
        ? `android-sdk/build-tools/${BUILD_TOOLS_VERSION}`
        : "explicit-path",
      apksignerSource: toolMode === "android-sdk"
        ? `android-sdk/build-tools/${BUILD_TOOLS_VERSION}`
        : "explicit-path",
      apkanalyzerSource: toolMode === "android-sdk"
        ? "android-sdk/cmdline-tools/latest"
        : "explicit-path",
    }),
  });
}

function boundedToolRun(executable, prefixArgs, args, maxStdoutBytes, environment) {
  const allArgs = [...prefixArgs, ...args];
  assertSafeScalar(executable, "TOOL_EXECUTABLE");
  if (allArgs.length > 32) fail("TOOL_ARGS_COUNT");
  for (const argument of allArgs) assertSafeScalar(argument, "TOOL_ARG");

  return new Promise((resolveRun, rejectRun) => {
    let settled = false;
    let stdoutBytes = 0;
    let stderrBytes = 0;
    const stdout = [];
    const stderr = [];
    let child;
    let timer = null;

    const rejectOnce = (code) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (child && !child.killed) child.kill("SIGKILL");
      rejectRun(new VerificationError(code));
    };

    try {
      child = spawn(executable, allArgs, {
        env: environment,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch {
      rejectOnce("TOOL_SPAWN");
      return;
    }

    timer = setTimeout(() => rejectOnce("TOOL_TIMEOUT"), TOOL_TIMEOUT_MS);
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > maxStdoutBytes) {
        rejectOnce("TOOL_STDOUT_LIMIT");
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_STDERR_BYTES) {
        rejectOnce("TOOL_STDERR_LIMIT");
        return;
      }
      stderr.push(chunk);
    });
    child.once("error", () => rejectOnce("TOOL_SPAWN"));
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (settled) return;
      if (signal) {
        rejectOnce("TOOL_SIGNAL");
        return;
      }
      if (code !== 0) {
        rejectOnce("TOOL_EXIT");
        return;
      }
      try {
        const stderrText = decodeToolBuffer(Buffer.concat(stderr), "TOOL_STDERR_ENCODING");
        if (stderrText.trim().length !== 0) {
          rejectOnce("TOOL_STDERR_NONEMPTY");
          return;
        }
        const stdoutText = decodeToolBuffer(Buffer.concat(stdout), "TOOL_STDOUT_ENCODING");
        settled = true;
        resolveRun(stdoutText);
      } catch (error) {
        rejectOnce(error instanceof VerificationError ? error.code : "TOOL_OUTPUT_UNEXPECTED");
      }
    });
  });
}

async function requireRegularFile(path, code, maximumBytes = null) {
  let info;
  try {
    info = await lstat(path);
  } catch {
    fail(code);
  }
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0) fail(code);
  if (maximumBytes !== null && info.size > maximumBytes) fail(code);
  return info;
}

async function firstRegularFile(candidates, code) {
  const matches = [];
  for (const candidate of candidates) {
    try {
      const info = await stat(candidate);
      if (info.isFile()) matches.push(await realpath(candidate));
    } catch {
      // A missing candidate is handled after checking the complete fixed list.
    }
  }
  if (matches.length !== 1) fail(code);
  return matches[0];
}

async function resolveJavaExecutable(environment) {
  const javaHome = environment.JAVA_HOME;
  if (javaHome) {
    assertSafeScalar(javaHome, "JAVA_HOME_FORMAT");
    return firstRegularFile(
      [join(javaHome, "bin", "java"), join(javaHome, "bin", "java.exe")],
      "JAVA_EXECUTABLE",
    );
  }
  return process.platform === "win32" ? "java.exe" : "java";
}

async function resolveToolPaths(configuration) {
  if (configuration.toolMode === "explicit-paths") {
    await requireRegularFile(configuration.aapt2Path, "AAPT2_PATH");
    await requireRegularFile(configuration.apksignerPath, "APKSIGNER_PATH");
    await requireRegularFile(configuration.apkanalyzerPath, "APKANALYZER_PATH");
    return {
      aapt2Path: await realpath(configuration.aapt2Path),
      apksignerPath: await realpath(configuration.apksignerPath),
      apkanalyzerPath: await realpath(configuration.apkanalyzerPath),
    };
  }

  let sdkRoot;
  try {
    sdkRoot = await realpath(configuration.androidSdkPath);
  } catch {
    fail("ANDROID_SDK_PATH");
  }
  const wrapperSuffix = process.platform === "win32" ? ".bat" : "";
  const executableSuffix = process.platform === "win32" ? ".exe" : "";
  const aapt2Path = join(
    sdkRoot,
    "build-tools",
    BUILD_TOOLS_VERSION,
    `aapt2${executableSuffix}`,
  );
  const apksignerPath = join(
    sdkRoot,
    "build-tools",
    BUILD_TOOLS_VERSION,
    `apksigner${wrapperSuffix}`,
  );
  const apkanalyzerPath = join(
    sdkRoot,
    "cmdline-tools",
    "latest",
    "bin",
    `apkanalyzer${wrapperSuffix}`,
  );
  await requireRegularFile(aapt2Path, "AAPT2_PATH");
  await requireRegularFile(apksignerPath, "APKSIGNER_PATH");
  await requireRegularFile(apkanalyzerPath, "APKANALYZER_PATH");
  return {
    aapt2Path: await realpath(aapt2Path),
    apksignerPath: await realpath(apksignerPath),
    apkanalyzerPath: await realpath(apkanalyzerPath),
  };
}

async function resolveToolInvocations(configuration, environment) {
  const paths = await resolveToolPaths(configuration);
  const javaExecutable = await resolveJavaExecutable(environment);
  const apksignerDirectory = dirname(paths.apksignerPath);
  const apksignerJar = await firstRegularFile(
    [
      join(apksignerDirectory, "apksigner.jar"),
      join(apksignerDirectory, "lib", "apksigner.jar"),
    ],
    "APKSIGNER_LAYOUT",
  );
  const apkanalyzerHome = resolve(dirname(paths.apkanalyzerPath), "..");
  const apkanalyzerJar = await firstRegularFile(
    [join(apkanalyzerHome, "lib", "apkanalyzer-classpath.jar")],
    "APKANALYZER_LAYOUT",
  );

  return {
    aapt2: {
      executable: paths.aapt2Path,
      prefixArgs: [],
    },
    apksigner: {
      executable: javaExecutable,
      prefixArgs: [
        "-Dfile.encoding=UTF-8",
        "-Dstdout.encoding=UTF-8",
        "-Dstderr.encoding=UTF-8",
        "-Xmx1024M",
        "-Xss1m",
        "-jar",
        apksignerJar,
      ],
    },
    apkanalyzer: {
      executable: javaExecutable,
      prefixArgs: [
        "-Dfile.encoding=UTF-8",
        "-Dstdout.encoding=UTF-8",
        "-Dstderr.encoding=UTF-8",
        `-Dcom.android.sdklib.toolsdir=${apkanalyzerHome}`,
        "-classpath",
        apkanalyzerJar,
        "com.android.tools.apk.analyzer.ApkAnalyzerCli",
      ],
    },
  };
}

function toolEnvironment(environment) {
  const output = {};
  for (const name of [
    "JAVA_HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "SystemRoot",
    "TEMP",
    "TMP",
    "WINDIR",
  ]) {
    if (typeof environment[name] === "string") output[name] = environment[name];
  }
  return output;
}

async function sha256File(path) {
  const digest = createHash("sha256");
  await new Promise((resolveHash, rejectHash) => {
    const stream = createReadStream(path);
    let bytes = 0;
    stream.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_APK_BYTES) {
        stream.destroy(new VerificationError("APK_HASH_SIZE"));
        return;
      }
      digest.update(chunk);
    });
    stream.once("error", (error) => rejectHash(
      error instanceof VerificationError ? error : new VerificationError("APK_HASH_READ"),
    ));
    stream.once("end", resolveHash);
  });
  return digest.digest("hex");
}

function safeTemporaryDirectory(path) {
  const temporaryRoot = resolve(tmpdir());
  const candidate = resolve(path);
  const relation = relative(temporaryRoot, candidate);
  return (
    relation.length > 0
    && !relation.startsWith(`..${sep}`)
    && relation !== ".."
    && !isAbsolute(relation)
    && basename(candidate).startsWith("veil-tester-apk-verify-")
  );
}

async function writeEvidenceExclusively(path, evidence) {
  const parent = dirname(path);
  let parentInfo;
  try {
    parentInfo = await stat(parent);
  } catch {
    fail("EVIDENCE_PARENT");
  }
  if (!parentInfo.isDirectory()) fail("EVIDENCE_PARENT");

  const temporaryPath = join(parent, `.veil-tester-evidence-${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify(evidence, null, 2)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;
    try {
      await link(temporaryPath, path);
    } catch (error) {
      if (error?.code === "EEXIST") fail("EVIDENCE_EXISTS");
      fail("EVIDENCE_TARGET");
    }
    await rm(temporaryPath, { force: true }).catch(() => {});
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await rm(temporaryPath, { force: true }).catch(() => {});
    if (error instanceof VerificationError) throw error;
    fail("EVIDENCE_WRITE");
  }
}

export async function verifyAndroidTesterApk(configuration, options = {}) {
  const environment = options.environment ?? process.env;
  const now = options.now ?? (() => new Date());
  const sourceInfo = await requireRegularFile(configuration.apkPath, "APK_PATH", MAX_APK_BYTES);
  try {
    await lstat(configuration.evidencePath);
    fail("EVIDENCE_EXISTS");
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    if (error?.code !== "ENOENT") fail("EVIDENCE_TARGET");
  }
  const invocations = await resolveToolInvocations(configuration, environment);
  const childEnvironment = toolEnvironment(environment);
  const snapshotDirectory = await mkdtemp(join(tmpdir(), "veil-tester-apk-verify-"));
  if (!safeTemporaryDirectory(snapshotDirectory)) fail("TEMP_PATH");
  const snapshotPath = join(snapshotDirectory, "candidate.apk");

  let evidence;
  try {
    await copyFile(configuration.apkPath, snapshotPath);
    const snapshotInfo = await requireRegularFile(snapshotPath, "APK_SNAPSHOT", MAX_APK_BYTES);
    if (snapshotInfo.size !== sourceInfo.size) fail("APK_CHANGED");
    const snapshotSha256 = await sha256File(snapshotPath);

    const signatureOutput = await boundedToolRun(
      invocations.apksigner.executable,
      invocations.apksigner.prefixArgs,
      ["verify", "--verbose", "--print-certs", "-Werr", "--in", snapshotPath],
      MAX_SIGNATURE_OUTPUT_BYTES,
      childEnvironment,
    );
    const signer = parseApkSignerOutput(
      signatureOutput,
      configuration.certificateSha256,
      configuration.forbiddenCertificateSha256,
    );

    const analyze = (args, maximum = MAX_SMALL_OUTPUT_BYTES) => boundedToolRun(
      invocations.apkanalyzer.executable,
      invocations.apkanalyzer.prefixArgs,
      [...args, snapshotPath],
      maximum,
      childEnvironment,
    );
    const applicationId = parseSingleLineOutput(
      await analyze(["manifest", "application-id"]),
      "APPLICATION_ID_OUTPUT",
    );
    if (applicationId !== EXPECTED_APPLICATION_ID) fail("APPLICATION_ID_MISMATCH");

    const sdkVersions = verifyTesterSdkVersions(
      await analyze(["manifest", "min-sdk"]),
      await analyze(["manifest", "target-sdk"]),
    );
    const permissions = verifyTesterPermissions(
      await analyze(["manifest", "permissions"], MAX_PERMISSIONS_OUTPUT_BYTES),
    );

    const versionCode = parseSingleLineOutput(
      await analyze(["manifest", "version-code"]),
      "VERSION_CODE_OUTPUT",
    );
    if (versionCode !== String(configuration.versionCode)) fail("VERSION_CODE_MISMATCH");

    const versionName = parseSingleLineOutput(
      await analyze(["manifest", "version-name"]),
      "VERSION_NAME_OUTPUT",
    );
    if (versionName !== configuration.versionName) fail("VERSION_NAME_MISMATCH");

    const debuggable = parseSingleLineOutput(
      await analyze(["manifest", "debuggable"]),
      "DEBUGGABLE_OUTPUT",
    );
    if (debuggable !== "false") fail("DEBUGGABLE_TRUE");

    const parsedManifest = parseManifestXml(
      await analyze(["manifest", "print"], MAX_MANIFEST_OUTPUT_BYTES),
    );
    const verifiedManifest = assertTesterManifest(
      parsedManifest,
      configuration.sourceCommit,
      configuration.versionCode,
      configuration.versionName,
    );
    const verifiedResources = verifyTesterResourceBindings(
      parsedManifest,
      await boundedToolRun(
        invocations.aapt2.executable,
        invocations.aapt2.prefixArgs,
        ["dump", "resources", snapshotPath],
        MAX_RESOURCE_TABLE_OUTPUT_BYTES,
        childEnvironment,
      ),
    );
    const verifiedBackupPolicy = verifyTesterDataExtractionRules(
      await boundedToolRun(
        invocations.aapt2.executable,
        invocations.aapt2.prefixArgs,
        [
          "dump",
          "xmltree",
          "--file",
          EXPECTED_DATA_EXTRACTION_RULES_FILE,
          snapshotPath,
        ],
        MAX_DATA_EXTRACTION_RULES_OUTPUT_BYTES,
        childEnvironment,
      ),
    );
    const branding = {};
    for (const name of Object.keys(EXPECTED_BRANDING_RESOURCES)) {
      branding[name] = parseSingleLineOutput(
        await analyze([
          "resources",
          "value",
          "--config",
          "default",
          "--type",
          "string",
          "--name",
          name,
        ]),
        "BRANDING_RESOURCE_OUTPUT",
      );
    }
    const verifiedBranding = assertTesterBranding(branding);
    verifyArchiveFileList(await analyze(["files", "list"], MAX_FILE_LIST_OUTPUT_BYTES));

    const finalSourceInfo = await requireRegularFile(
      configuration.apkPath,
      "APK_PATH",
      MAX_APK_BYTES,
    );
    const finalSourceSha256 = await sha256File(configuration.apkPath);
    if (finalSourceInfo.size !== snapshotInfo.size || finalSourceSha256 !== snapshotSha256) {
      fail("APK_CHANGED");
    }

    const timestamp = now();
    if (!(timestamp instanceof Date) || Number.isNaN(timestamp.getTime())) fail("CLOCK_INVALID");
    evidence = buildEvidence({
      apkSha256: snapshotSha256,
      apkSizeBytes: snapshotInfo.size,
      certificateSha256: signer.certificateSha256,
      forbiddenCertificateSha256: configuration.forbiddenCertificateSha256,
      signatureSchemePolicy: signer.signatureSchemePolicy,
      branding: verifiedBranding,
      resources: verifiedResources,
      backupPolicy: verifiedBackupPolicy,
      sdkVersions,
      permissions,
      components: verifiedManifest.components,
      backupManifestPolicy: Object.freeze({
        hasBackupAgent: verifiedManifest.hasBackupAgent,
        backupOverrideAttributesPresent: verifiedManifest.backupOverrideAttributesPresent,
      }),
      versionCode: configuration.versionCode,
      versionName: configuration.versionName,
      sourceCommit: configuration.sourceCommit,
      toolMode: configuration.toolMode,
      verifiedAtUtc: timestamp.toISOString(),
    });
  } finally {
    if (!safeTemporaryDirectory(snapshotDirectory)) fail("TEMP_PATH");
    try {
      await rm(snapshotDirectory, { recursive: true, force: true });
    } catch {
      fail("TEMP_CLEANUP");
    }
  }

  await writeEvidenceExclusively(configuration.evidencePath, evidence);
  return evidence;
}

async function main() {
  const configuration = parseArguments(process.argv.slice(2));
  await verifyAndroidTesterApk(configuration);
  process.stdout.write("Android tester APK verified; sanitized evidence written.\n");
}

const entryPoint = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
if (entryPoint === import.meta.url) {
  main().catch((error) => {
    const code = error instanceof VerificationError ? error.code : "UNEXPECTED";
    process.stderr.write(`Android tester APK verification failed: ${code}\n`);
    process.exitCode = 1;
  });
}
