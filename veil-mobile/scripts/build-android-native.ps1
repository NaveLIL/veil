param(
  [string]$CargoTargetDir = "D:\veil-mobile-rust-target"
)

$ErrorActionPreference = "Stop"
$mobileRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$workspaceRoot = (Resolve-Path (Join-Path $mobileRoot "..")).Path
$jniOutput = Join-Path $mobileRoot "android\app\src\main\jniLibs"
$bindingOutput = Join-Path $mobileRoot "src\native\generated"

$env:CARGO_TARGET_DIR = $CargoTargetDir

Push-Location $workspaceRoot
try {
  cargo build -p veil-ffi --release
  if ($LASTEXITCODE -ne 0) { throw "Host veil-ffi build failed" }

  cargo run --release -p veil-ffi --bin uniffi-bindgen -- generate `
    --library (Join-Path $CargoTargetDir "release\veil_ffi.dll") `
    --language kotlin `
    --no-format `
    --out-dir $bindingOutput
  if ($LASTEXITCODE -ne 0) { throw "UniFFI Kotlin binding generation failed" }

  # UniFFI 0.29 emits trailing whitespace in Kotlin bindings. Normalize only
  # line tails/EOF so generated source remains stable under git diff --check.
  $bindingFile = Join-Path $bindingOutput "uniffi\veil_ffi\veil_ffi.kt"
  $bindingText = [System.IO.File]::ReadAllText($bindingFile)
  $bindingText = [System.Text.RegularExpressions.Regex]::Replace(
    $bindingText,
    "[ \t]+(?=\r?\n|$)",
    ""
  )
  $bindingText = $bindingText.TrimEnd("`r", "`n") + "`n"
  [System.IO.File]::WriteAllText(
    $bindingFile,
    $bindingText,
    [System.Text.UTF8Encoding]::new($false)
  )

  cargo ndk -t arm64-v8a -t x86_64 -o $jniOutput build -p veil-ffi --release
  if ($LASTEXITCODE -ne 0) { throw "Android veil-ffi build failed" }
} finally {
  Pop-Location
}
