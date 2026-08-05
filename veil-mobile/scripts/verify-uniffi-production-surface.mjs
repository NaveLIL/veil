import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const bindingPath = resolve(
  scriptDirectory,
  "../src/native/generated/uniffi/veil_ffi/veil_ffi.kt",
);
const binding = readFileSync(bindingPath, "utf8");

const forbidden = [
  "interface VeilRatchetInterface",
  "open class VeilRatchet",
  "data class AeadResult",
  "data class RatchetMessage",
  "data class ShareBundle",
  "data class X3dhResultData",
  "data class PreKeyBundleData",
  "fun `aeadDecrypt`",
  "fun `aeadEncrypt`",
  "fun `decryptShare`",
  "fun `deriveKeyFromPassword`",
  "fun `deriveKeyFromPin`",
  "fun `ed25519Verify`",
  "fun `encryptShare`",
  "fun `generateAccountFingerprintV2`",
  "fun `generateMnemonic`",
  "fun `sign`(`message`:",
  "fun `validateMnemonic`",
  "fun `x3dhInitiate`",
  "fun `fromMnemonic`(`mnemonic`:",
];

const required = [
  "open class VeilIdentity",
  "fun `fromMnemonicBytes`",
  "fun `identityKey`",
  "fun `signingKey`",
  "open class VeilMobileSession",
  "fun `confirmDirectIdentityVerification`",
  "fun `directIdentityVerification`",
  "fun `sendDirectText`",
  "fun `startBackgroundEvents`",
];

const leaked = forbidden.filter((needle) => binding.includes(needle));
const missing = required.filter((needle) => !binding.includes(needle));

if (leaked.length > 0 || missing.length > 0) {
  for (const needle of leaked) {
    console.error(`forbidden production UniFFI symbol is exported: ${needle}`);
  }
  for (const needle of missing) {
    console.error(`required high-level UniFFI symbol is missing: ${needle}`);
  }
  process.exitCode = 1;
} else {
  console.log("production UniFFI surface is high-level and secret-safe");
}
