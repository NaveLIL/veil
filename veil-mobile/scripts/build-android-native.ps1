param(
  [string]$CargoTargetDir = ""
)

$ErrorActionPreference = "Stop"

function Select-CompatiblePerl {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Windows", "Unix")]
    [string]$Kind,

    [Parameter(Mandatory = $true)]
    [string[]]$Candidates
  )

  $pathProbe = if ($Kind -eq "Windows") {
    @'
if ($^O ne q(MSWin32)) {
    print q(expected native Windows Perl, got ) . $^O;
    exit 41;
}
if (index($absolute, chr(92)) < 0) {
    print q(File::Spec does not produce Windows-style paths: ) . $absolute;
    exit 42;
}
'@
  } else {
    @'
if ($^O eq q(MSWin32)) {
    print q(expected MSYS2/Cygwin Perl, got native Windows Perl);
    exit 41;
}
if (index($absolute, q(/)) < 0) {
    print q(File::Spec does not produce Unix-style paths: ) . $absolute;
    exit 42;
}
'@
  }

  $perlProbe = @"
use strict;
use warnings;
use Config;
use File::Spec::Functions qw(rel2abs);

my `$absolute = rel2abs(q(.));
$pathProbe
eval {
    require Locale::Maketext::Simple;
    require ExtUtils::MakeMaker;
    require Pod::Usage;
    require IPC::Cmd;
    1;
} or do {
    print q(required Perl module unavailable: ) . `$@;
    exit 43;
};
"@

  $failures = @()
  foreach ($candidate in ($Candidates | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
      } | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
      $failures += "  - ${candidate}: executable not found"
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
      return [pscustomobject]@{
        Path = [System.IO.Path]::GetFullPath($candidate)
        Failures = $failures
      }
    }

    if ([string]::IsNullOrWhiteSpace($probeOutput)) {
      $probeOutput = "compatibility probe failed with exit code $probeExitCode"
    } else {
      $probeOutput = $probeOutput -replace "\r?\n", " | "
    }
    $failures += "  - ${candidate}: $probeOutput"
  }

  return [pscustomobject]@{
    Path = $null
    Failures = $failures
  }
}

function Format-PerlFailures {
  param([object[]]$Failures)

  if ($null -eq $Failures -or $Failures.Count -eq 0) {
    return "  - no Perl candidates were found"
  }
  return $Failures -join [Environment]::NewLine
}

$mobileRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$workspaceRoot = (Resolve-Path (Join-Path $mobileRoot "..")).Path
$jniOutput = Join-Path $mobileRoot "android/app/src/main/jniLibs"
$bindingOutput = Join-Path $mobileRoot "src/native/generated"

$originalEnvironment = @{
  CARGO_TARGET_DIR = [Environment]::GetEnvironmentVariable("CARGO_TARGET_DIR", "Process")
  OPENSSL_SRC_PERL = [Environment]::GetEnvironmentVariable("OPENSSL_SRC_PERL", "Process")
  MSYSTEM = [Environment]::GetEnvironmentVariable("MSYSTEM", "Process")
  CYGWIN = [Environment]::GetEnvironmentVariable("CYGWIN", "Process")
  PATH = [Environment]::GetEnvironmentVariable("PATH", "Process")
}

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

$hostPerl = $null
$androidPerl = $null
$androidToolBin = $null
if ($env:OS -eq "Windows_NT") {
  # OpenSSL's native VC-WIN64A target requires native Windows path semantics.
  # OPENSSL_SRC_WINDOWS_PERL is a script-only override; OPENSSL_SRC_PERL is
  # still accepted as a candidate for backwards compatibility.
  $hostPerlCandidates = @()
  if (-not [string]::IsNullOrWhiteSpace($env:OPENSSL_SRC_WINDOWS_PERL)) {
    $hostPerlCandidates += $env:OPENSSL_SRC_WINDOWS_PERL
  } else {
    if (-not [string]::IsNullOrWhiteSpace($env:OPENSSL_SRC_PERL)) {
      $hostPerlCandidates += $env:OPENSSL_SRC_PERL
    }
    $hostPerlCandidates += @(
      "C:/Strawberry/perl/bin/perl.exe",
      "C:/Perl64/bin/perl.exe",
      "C:/Perl/bin/perl.exe"
    )
    foreach ($pathPerl in @(Get-Command perl -All -ErrorAction SilentlyContinue)) {
      $hostPerlCandidates += $pathPerl.Source
    }
  }

  $hostPerlSelection = Select-CompatiblePerl -Kind Windows -Candidates $hostPerlCandidates
  if ($null -eq $hostPerlSelection.Path) {
    $checkedPerl = Format-PerlFailures $hostPerlSelection.Failures
    throw @"
The host veil-ffi build requires a native Windows Perl because OpenSSL uses
its VC-WIN64A target. Install Strawberry Perl or set
OPENSSL_SRC_WINDOWS_PERL to a compatible perl.exe.

Checked native Windows Perl candidates:
$checkedPerl
"@
  }
  $hostPerl = $hostPerlSelection.Path

  # SQLCipher's vendored OpenSSL build uses OpenSSL's Unix Android target even
  # when Cargo runs on Windows. It needs a complete MSYS2/Cygwin Perl, make and
  # sh. Native Strawberry Perl and Git's trimmed Perl are not compatible.
  $androidPerlCandidates = @()
  if (-not [string]::IsNullOrWhiteSpace($env:OPENSSL_SRC_ANDROID_PERL)) {
    $androidPerlCandidates += $env:OPENSSL_SRC_ANDROID_PERL
  } else {
    if (-not [string]::IsNullOrWhiteSpace($env:OPENSSL_SRC_PERL)) {
      $androidPerlCandidates += $env:OPENSSL_SRC_PERL
    }
    if (-not [string]::IsNullOrWhiteSpace($env:MSYS2_ROOT)) {
      $androidPerlCandidates += (Join-Path $env:MSYS2_ROOT "usr/bin/perl.exe")
    }
    $androidPerlCandidates += @(
      "C:/msys64/usr/bin/perl.exe",
      "C:/tools/msys64/usr/bin/perl.exe",
      "C:/cygwin64/bin/perl.exe",
      "C:/Program Files/Git/usr/bin/perl.exe"
    )
    foreach ($pathPerl in @(Get-Command perl -All -ErrorAction SilentlyContinue)) {
      $androidPerlCandidates += $pathPerl.Source
    }
  }

  $androidPerlSelection = Select-CompatiblePerl -Kind Unix -Candidates $androidPerlCandidates
  if ($null -eq $androidPerlSelection.Path) {
    $checkedPerl = Format-PerlFailures $androidPerlSelection.Failures
    throw @"
Android veil-ffi requires a full Unix-compatible Perl because SQLCipher builds
vendored OpenSSL for Android. Native Strawberry Perl and Git for Windows Perl
are not compatible with this phase.

Install MSYS2, then install its complete Perl and make packages:
  pacman -S --needed perl make

Set OPENSSL_SRC_ANDROID_PERL to the full executable path (for example
C:\msys64\usr\bin\perl.exe) and run pnpm native:android again. The legacy
OPENSSL_SRC_PERL override is also accepted as a candidate.

Checked Unix Perl candidates:
$checkedPerl
"@
  }
  $androidPerl = $androidPerlSelection.Path
  $androidToolBin = Split-Path $androidPerl -Parent

  $androidMake = Join-Path $androidToolBin "make.exe"
  $androidSh = Join-Path $androidToolBin "sh.exe"
  $missingAndroidTools = @()
  if (-not (Test-Path -LiteralPath $androidMake -PathType Leaf)) {
    $missingAndroidTools += $androidMake
  }
  if (-not (Test-Path -LiteralPath $androidSh -PathType Leaf)) {
    $missingAndroidTools += $androidSh
  }
  if ($missingAndroidTools.Count -gt 0) {
    $missingList = ($missingAndroidTools | ForEach-Object { "  - $_" }) -join [Environment]::NewLine
    throw @"
Compatible Unix Perl found at $androidPerl, but its matching Android build
tools are missing. Install the MSYS2 make package and verify these files:
$missingList
"@
  }

  $previousErrorActionPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $makeProbeOutput = (& $androidMake --version 2>&1 | Out-String).Trim()
    $makeProbeExitCode = $LASTEXITCODE
    $shProbeOutput = (& $androidSh -lc "exit 0" 2>&1 | Out-String).Trim()
    $shProbeExitCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }
  if ($makeProbeExitCode -ne 0 -or $shProbeExitCode -ne 0) {
    throw @"
The MSYS2/Cygwin toolchain next to $androidPerl failed its startup probes.
make.exe: exit $makeProbeExitCode; $makeProbeOutput
sh.exe: exit $shProbeExitCode; $shProbeOutput
"@
  }
}

try {
  $env:CARGO_TARGET_DIR = $CargoTargetDir

  Push-Location $workspaceRoot
  try {
    if ($env:OS -eq "Windows_NT") {
      # The host OpenSSL build must not inherit MSYS/Cygwin path semantics.
      $env:OPENSSL_SRC_PERL = $hostPerl
      $env:PATH = (Split-Path $hostPerl -Parent) + [System.IO.Path]::PathSeparator + $originalEnvironment.PATH
      [Environment]::SetEnvironmentVariable("MSYSTEM", $null, "Process")
      [Environment]::SetEnvironmentVariable("CYGWIN", $null, "Process")
    }

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

    if ($env:OS -eq "Windows_NT") {
      # Switch only the Android phase to Unix path semantics. cargo-ndk uses
      # MSYSTEM/CYGWIN as its signal to normalize NDK paths before /bin/sh
      # consumes them.
      $env:OPENSSL_SRC_PERL = $androidPerl
      $env:PATH = $androidToolBin + [System.IO.Path]::PathSeparator + $originalEnvironment.PATH
      [Environment]::SetEnvironmentVariable("MSYSTEM", $originalEnvironment.MSYSTEM, "Process")
      [Environment]::SetEnvironmentVariable("CYGWIN", $originalEnvironment.CYGWIN, "Process")
      if (
        [string]::IsNullOrWhiteSpace($env:MSYSTEM) -and
        [string]::IsNullOrWhiteSpace($env:CYGWIN)
      ) {
        $env:MSYSTEM = "MSYS"
      }
    }

    cargo ndk -t arm64-v8a -t x86_64 -o $jniOutput build -p veil-ffi --release
    if ($LASTEXITCODE -ne 0) { throw "Android veil-ffi build failed" }
  } finally {
    Pop-Location
  }
} finally {
  foreach ($environmentName in $originalEnvironment.Keys) {
    [Environment]::SetEnvironmentVariable(
      $environmentName,
      $originalEnvironment[$environmentName],
      "Process"
    )
  }
}
