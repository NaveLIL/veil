import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const script = fileURLToPath(new URL('./account-tester-readiness.mjs', import.meta.url));
const signingKeys = ['VEIL_ANDROID_TESTER_KEYSTORE', 'VEIL_ANDROID_TESTER_KEYSTORE_PASSWORD',
  'VEIL_ANDROID_TESTER_KEY_ALIAS', 'VEIL_ANDROID_TESTER_KEY_PASSWORD'];
function run(signingValue) {
  const env = { ...process.env };
  for (const key of signingKeys) {
    delete env[key];
    if (signingValue !== undefined) env[key] = signingValue;
  }
  return spawnSync(process.execPath, [script], { env, encoding: 'utf8', windowsHide: true });
}

test('readiness does not infer missing credentials or claim authenticated E2E from file checks', () => {
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Authenticated Direct E2E: NOT RUN by this read-only readiness check/);
  assert.match(result.stdout, /Credential availability and prior exchange results are not assessed/);
  assert.doesNotMatch(result.stdout, /BLOCKED BY TEST CREDENTIALS|E2E verified/i);
});

test('signing readiness reports presence without exposing values or opening a key file', () => {
  const marker = 'TEST_ONLY_SIGNING_VALUE_DO_NOT_PRINT';
  const result = run(marker);
  assert.equal(result.status, 0, result.stderr);
  for (const key of signingKeys) assert.ok(result.stdout.includes(`${key}: configured (value hidden)`));
  assert.ok(!result.stdout.includes(marker));
  assert.equal(result.stderr, '');
});
