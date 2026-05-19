# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param(
    [string]$Distro = "Ubuntu-24.04",
    [string]$BuildDir = "build-wsl",
    [string]$CC = "clang",
    [string]$CXX = "clang++",
    [string]$WrapMode = "forcefallback",
    [ValidateSet("", "debug", "release", "sanitizer", "coverage", "fuzz", "hardened")]
    [string]$Profile = "",
    [switch]$BuildFuzz,
    [switch]$NoTests,
    [switch]$SetupOnly,
    [switch]$CompileOnly,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Quote-Bash([string]$Value) {
    return "'" + ($Value -replace "'", "'\''") + "'"
}

function ConvertTo-WslPath([string]$WindowsPath) {
    $ResolvedPath = (Resolve-Path -LiteralPath $WindowsPath).Path
    if ($ResolvedPath -match '^([A-Za-z]):\\(.*)$') {
        $Drive = $Matches[1].ToLowerInvariant()
        $Tail = $Matches[2] -replace '\\', '/'
        return "/mnt/$Drive/$Tail"
    }

    $WslPath = (& wsl.exe -d $Distro -- wslpath -a -- "$ResolvedPath")
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($WslPath)) {
        throw "Unable to resolve repository path inside WSL distro '$Distro': $ResolvedPath"
    }
    return $WslPath.Trim()
}

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptRoot

$LinuxRepoRoot = ConvertTo-WslPath $RepoRoot

$ArgsList = @(
    "--builddir", $BuildDir,
    "--cc", $CC,
    "--cxx", $CXX,
    "--wrap-mode", $WrapMode
)

if ($Profile -ne "") {
    $ArgsList += @("--profile", $Profile)
}
if ($BuildFuzz) {
    $ArgsList += "--build-fuzz"
}
if ($NoTests) {
    $ArgsList += "--no-tests"
}
if ($SetupOnly) {
    $ArgsList += "--setup-only"
}
if ($CompileOnly) {
    $ArgsList += "--compile-only"
}
if ($DryRun) {
    $ArgsList += "--dry-run"
}

$QuotedArgs = ($ArgsList | ForEach-Object { Quote-Bash $_ }) -join " "
$Command = "cd $(Quote-Bash $LinuxRepoRoot) && sh scripts/build-linux.sh $QuotedArgs"

wsl.exe -d $Distro -- bash -lc $Command
exit $LASTEXITCODE
