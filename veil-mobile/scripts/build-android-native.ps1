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

# SQLCipher's vendored OpenSSL build uses OpenSSL's Unix Android target even
# when Cargo runs on Windows. It therefore needs a full MSYS2/Cygwin Perl, not
# Strawberry Perl (Windows paths) or Git for Windows' intentionally trimmed
# Perl distribution (missing core modules used by OpenSSL).
if ($env:OS -eq "Windows_NT") {
  $perlProbe = @'
use strict;
use warnings;
use Config;
use File::Spec::Functions qw(rel2abs);

my $absolute = rel2abs(q(.));
if (index($absolute, q(/)) < 0) {
    print q(File::Spec does not produce Unix-style paths);
    exit 41;
}

eval {
    require Locale::Maketext::Simple;
    require ExtUtils::MakeMaker;
    require Pod::Usage;
    require IPC::Cmd;
    1;
} or do {
    print q(required Perl module unavailable: ) . $@;
    exit 42;
};
'@

  $perlCandidates = @()
  if (-not [string]::IsNullOrWhiteSpace($env:OPENSSL_SRC_PERL)) {
    $perlCandidates += $env:OPENSSL_SRC_PERL
  } else {
    if (-not [string]::IsNullOrWhiteSpace($env:MSYS2_ROOT)) {
      $perlCandidates += (Join-Path $env:MSYS2_ROOT "usr/bin/perl.exe")
    }
    $perlCandidates += @(
      "C:/msys64/usr/bin/perl.exe",
      "C:/tools/msys64/usr/bin/perl.exe",
      "C:/cygwin64/bin/perl.exe"
    )

    $pathPerl = Get-Command perl -ErrorAction SilentlyContinue
    if ($null -ne $pathPerl) {
      $perlCandidates += $pathPerl.Source
    }
  }

  $perlFailures = @()
  $selectedPerl = $null
  foreach ($candidate in ($perlCandidates | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
      $perlFailures += "  - ${candidate}: executable not found"
      continue
    }

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
      $probeOutput = (& $candidate -e $perlProbe 2>&1 | Out-String).Trim()
      $probeExitCode = $LASTEXITCODE
    } finally {
      $ErrorActionPreference = $previousErrorActionPreference
    }

    if ($probeExitCode -eq 0) {
      $selectedPerl = [System.IO.Path]::GetFullPath($candidate)
      break
    }

    if ([string]::IsNullOrWhiteSpace($probeOutput)) {
      $probeOutput = "compatibility probe failed with exit code $probeExitCode"
    } else {
      $probeOutput = $probeOutput -replace "\r?\n", " | "
    }
    $perlFailures += "  - ${candidate}: $probeOutput"
  }

  if ($null -eq $selectedPerl) {
    $checkedPerl = if ($perlFailures.Count -gt 0) {
      $perlFailures -join [Environment]::NewLine
    } else {
      "  - no Perl candidates were found"
    }

    throw @"
Android native build requires a full Unix-compatible Perl because SQLCipher
builds vendored OpenSSL for Android. Strawberry Perl and Git for Windows Perl
are not compatible with this build.

Install MSYS2, then install its complete Perl and make packages:
  pacman -S --needed perl make

Set OPENSSL_SRC_PERL to the full executable path (for example
C:\msys64\usr\bin\perl.exe), ensure the matching make.exe is on PATH, and run
pnpm native:android again. The Linux Mobile CI build is also supported.

Checked Perl candidates:
$checkedPerl
"@
  }

  $env:OPENSSL_SRC_PERL = $selectedPerl
  $makeCommand = Get-Command make -ErrorAction SilentlyContinue
  if ($null -eq $makeCommand) {
    $perlBin = Split-Path $selectedPerl -Parent
    throw @"
Compatible Perl found at $selectedPerl, but make.exe is not on PATH.
Add the matching MSYS2/Cygwin bin directory to PATH (expected near $perlBin)
and run pnpm native:android again.
"@
  }

  # cargo-ndk emits Windows-style NDK tool paths unless it knows that its
  # child build uses an MSYS2/Cygwin shell. OpenSSL's generated Makefile then
  # passes those paths through /bin/sh, where backslashes are consumed as
  # escapes (for example C:\Android becomes C:Android). The probe above has
  # already established that this is a Unix-path Perl; cargo-ndk only checks
  # for the presence of either marker, so use MSYSTEM as the normalization
  # signal when the caller did not provide one. This also supports custom or
  # junctioned MSYS2/Cygwin installation roots.
  if (
    [string]::IsNullOrWhiteSpace($env:MSYSTEM) -and
    [string]::IsNullOrWhiteSpace($env:CYGWIN)
  ) {
    $env:MSYSTEM = "MSYS"
  }
}

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
