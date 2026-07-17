param(
  [string]$CargoTargetDir = ""
)

$ErrorActionPreference = "Stop"
$mobileRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$workspaceRoot = (Resolve-Path (Join-Path $mobileRoot "..")).Path
$jniOutput = Join-Path $mobileRoot "android/app/src/main/jniLibs"
$bindingOutput = Join-Path $mobileRoot "src/native/generated"

if ([string]::IsNullOrWhiteSpace($CargoTargetDir)) {
  if (-not [string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
    $CargoTargetDir = $env:CARGO_TARGET_DIR
  } else {
    # Keep native artifacts outside paths that may contain non-ASCII characters.
    # RUNNER_TEMP is an ASCII path on GitHub-hosted runners; the system temp
    # directory is the portable local fallback.
    $targetRoot = if (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
      $env:RUNNER_TEMP
    } else {
      [System.IO.Path]::GetTempPath()
    }
    $CargoTargetDir = Join-Path $targetRoot "veil-mobile-rust-target"
  }
}

$CargoTargetDir = [System.IO.Path]::GetFullPath($CargoTargetDir)
[System.IO.Directory]::CreateDirectory($CargoTargetDir) | Out-Null
$env:CARGO_TARGET_DIR = $CargoTargetDir

Push-Location $workspaceRoot
try {
  cargo build -p veil-ffi --release
  if ($LASTEXITCODE -ne 0) { throw "Host veil-ffi build failed" }

  $hostLibraryName = if ($env:OS -eq "Windows_NT") {
    "veil_ffi.dll"
  } elseif ((& uname -s) -eq "Darwin") {
    "libveil_ffi.dylib"
  } else {
    "libveil_ffi.so"
  }
  $hostLibrary = Join-Path (Join-Path $CargoTargetDir "release") $hostLibraryName
  if (-not (Test-Path -LiteralPath $hostLibrary -PathType Leaf)) {
    throw "Host veil-ffi library was not produced at $hostLibrary"
  }

  cargo run --release -p veil-ffi --bin uniffi-bindgen -- generate `
    --library $hostLibrary `
    --language kotlin `
    --no-format `
    --out-dir $bindingOutput
  if ($LASTEXITCODE -ne 0) { throw "UniFFI Kotlin binding generation failed" }

  # UniFFI 0.29 emits trailing whitespace in Kotlin bindings. Normalize only
  # line tails/EOF so generated source remains stable under git diff --check.
  $bindingFile = Join-Path (Join-Path (Join-Path $bindingOutput "uniffi") "veil_ffi") "veil_ffi.kt"
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
