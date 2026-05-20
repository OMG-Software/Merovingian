# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param(
    [string]$Distro = "",
    [string]$BuildDir = "build-wsl",
    [string]$CC = "clang",
    [string]$CXX = "clang++",
    [string]$WrapMode = "forcefallback",
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

    if ([string]::IsNullOrWhiteSpace($Distro)) {
        $WslPath = (& wsl.exe -- wslpath -a -- "$ResolvedPath")
    }
    else {
        $WslPath = (& wsl.exe -d $Distro -- wslpath -a -- "$ResolvedPath")
    }
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($WslPath)) {
        $TargetDistro = if ([string]::IsNullOrWhiteSpace($Distro)) { "<default>" } else { $Distro }
        throw "Unable to resolve repository path inside WSL distro '$TargetDistro': $ResolvedPath"
    }
    return $WslPath.Trim()
}

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptRoot
$BuildScript = Join-Path $ScriptRoot "build-wsl.sh"

if (-not (Test-Path -LiteralPath $BuildScript)) {
    throw "Missing WSL build wrapper: $BuildScript"
}

$LinuxRepoRoot = ConvertTo-WslPath $RepoRoot

$ArgsList = @(
    "--builddir", $BuildDir,
    "--cc", $CC,
    "--cxx", $CXX,
    "--wrap-mode", $WrapMode
)

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
$Command = "cd $(Quote-Bash $LinuxRepoRoot) && sh ./scripts/build-wsl.sh $QuotedArgs"

if ([string]::IsNullOrWhiteSpace($Distro)) {
    wsl.exe -- bash -lc $Command
}
else {
    wsl.exe -d $Distro -- bash -lc $Command
}
exit $LASTEXITCODE
