# Process-local build tools and validation. No downloads, registry or services.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-BuildTool([string]$Explicit, [string]$Name, [string[]]$Candidates = @()) {
    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit -PathType Leaf)) { throw "Missing $Name tool: $Explicit" }
        return (Resolve-Path -LiteralPath $Explicit).Path
    }
    $found = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found -and $found.Source -notlike '*\Microsoft\WindowsApps\*') { return $found.Source }
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return (Resolve-Path -LiteralPath $candidate).Path }
    }
    throw "Install $Name or pass its explicit path. This script does not download tools."
}

function Import-VsBuildEnvironment([string]$VsDevCmdPath) {
    if (-not $VsDevCmdPath) {
        $installer = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (Test-Path -LiteralPath $installer -PathType Leaf) {
            $installation = & $installer -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
            if ($LASTEXITCODE -ne 0) { throw 'vswhere could not locate MSVC' }
            if ($installation) { $VsDevCmdPath = Join-Path ($installation | Select-Object -First 1) 'Common7\Tools\VsDevCmd.bat' }
        }
    }
    if ($VsDevCmdPath) {
        $VsDevCmdPath = (Resolve-Path -LiteralPath $VsDevCmdPath).Path
        if ($VsDevCmdPath -match '[%"\r\n]') { throw 'Unsupported characters in VsDevCmd path' }
        # Capture, never print the environment: it may include unrelated secrets.
        $command = 'call "{0}" -no_logo -arch=x64 -host_arch=x64 >nul && set' -f $VsDevCmdPath
        $variables = & $env:ComSpec /d /v:off /c $command
        if ($LASTEXITCODE -ne 0) { throw 'VsDevCmd failed' }
        foreach ($line in $variables) {
            if ($line -match '^([A-Za-z_][A-Za-z0-9_()]*)=(.*)$') {
                [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
            }
        }
    }
    foreach ($tool in @('cl.exe', 'nmake.exe', 'dumpbin.exe')) { $null = Resolve-BuildTool '' $tool }
    if ($env:VSCMD_ARG_TGT_ARCH -ne 'x64') { throw 'An x64 MSVC developer environment is required; pass -VsDevCmdPath.' }
    return $VsDevCmdPath
}

function Get-WindowsBuildSettings([string]$PerlPath, [string]$PythonPath, [string]$VsDevCmdPath) {
    if ($env:OS -ne 'Windows_NT') { throw 'These scripts require native Windows x64 MSVC (not WSL or MinGW).' }
    $project = Split-Path -Parent $PSScriptRoot
    $vs = Import-VsBuildEnvironment $VsDevCmdPath
    $python = Resolve-BuildTool $PythonPath 'python.exe'
    $pythonVersion = & $python --version
    if ($LASTEXITCODE -ne 0 -or "$pythonVersion" -notmatch '^Python 3\.(\d+)\.' -or [int]$Matches[1] -lt 11) { throw 'Python 3.11+ is required' }
    $perl = Resolve-BuildTool $PerlPath 'perl.exe' @('C:\Strawberry\perl\bin\perl.exe', (Join-Path $env:ProgramFiles 'Strawberry\perl\bin\perl.exe'))
    $perlOs = & $perl -e 'print $^O;'
    if ($LASTEXITCODE -ne 0 -or $perlOs -ne 'MSWin32') { throw 'Native Windows Perl is required (for example Strawberry Perl); MSYS/Cygwin Perl is unsupported.' }
    $perlVersion = & $perl -e 'print $^V;'
    if ($LASTEXITCODE -ne 0) { throw 'Could not query Perl version' }
    $compiler = Resolve-BuildTool '' 'cl.exe'
    return [pscustomobject]@{
        Project = $project; Source = (Join-Path $project 'third_party\openssl'); Target = 'x86_64-pc-windows-msvc'
        Root = (Join-Path $project 'work\openssl-windows-x64-static-noasm'); Perl = $perl; Python = $python
        VsDevCmd = $vs; Compiler = $compiler; CompilerVersion = (Get-Item -LiteralPath $compiler).VersionInfo.FileVersion
        PerlVersion = "$perlVersion"; VCToolsVersion = "$env:VCToolsVersion"; WindowsSDKVersion = "$env:WindowsSDKVersion"
    }
}

function Invoke-BuildStep([string]$Tool, [string[]]$Arguments, [string]$Log) {
    # Windows PowerShell 5.1 wraps native stderr as ErrorRecord. Preserve it in
    # the log without treating compiler warnings as terminating PS exceptions.
    $ErrorActionPreference = 'Continue'
    & $Tool @Arguments *> $Log
    $result = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($result -ne 0) { throw "Build step failed ($result). See $Log" }
}

function Get-PeMachine([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $reader = New-Object IO.BinaryReader($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw "Not a PE file: $Path" }
        $stream.Position = 0x3c
        $offset = $reader.ReadUInt32()
        if ($offset -gt 1048576 -or $offset + 6 -gt $stream.Length) { throw "Invalid PE header: $Path" }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "Invalid PE signature: $Path" }
        return $reader.ReadUInt16()
    } finally { $reader.Dispose(); $stream.Dispose() }
}

function Get-PeImports([string]$Path) {
    $output = & dumpbin.exe /nologo /dependents $Path 2>&1
    if ($LASTEXITCODE -ne 0) { throw "dumpbin failed: $Path" }
    return @($output | ForEach-Object { if ("$_" -match '^\s+([A-Za-z0-9_.-]+\.dll)\s*$') { $Matches[1] } } | Sort-Object -Unique)
}

function Assert-StaticWindowsBinary([string]$Path) {
    if ((Get-PeMachine $Path) -ne 0x8664) { throw "Expected AMD64 PE: $Path" }
    $imports = @(Get-PeImports $Path)
    if ($imports.Count -eq 0) { throw "No PE imports found; cannot validate $Path" }
    foreach ($name in $imports) {
        if ($name -match '^(?i:libssl|libcrypto|vcruntime|msvcp|msvcr|ucrtbase|api-ms-win-crt).*\.dll$') {
            throw "Unexpected dynamic TLS/CRT import $name in $Path"
        }
    }
    return $imports
}

function Set-WindowsCargoEnvironment($Settings) {
    $prefix = Join-Path $Settings.Root 'install'
    $opensslEnvironment = @{
        OPENSSL_DIR = $prefix; OPENSSL_STATIC = '1'; OPENSSL_NO_VENDOR = '1'
        OPENSSL_LIB_DIR = (Join-Path $prefix 'lib'); OPENSSL_INCLUDE_DIR = (Join-Path $prefix 'include')
        OPENSSL_LIBS = 'libssl:libcrypto'
    }
    foreach ($pair in $opensslEnvironment.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($pair.Key, $pair.Value, 'Process')
        [Environment]::SetEnvironmentVariable(('X86_64_PC_WINDOWS_MSVC_' + $pair.Key), $pair.Value, 'Process')
    }
    $env:SSLRAY_TLS_SOURCE_DIR = $Settings.Source
    $env:CARGO_BUILD_TARGET = $Settings.Target
    if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Join-Path $Settings.Project 'work\windows-x64-target' }
    elseif (-not [IO.Path]::IsPathRooted($env:CARGO_TARGET_DIR)) { $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath((Join-Path $Settings.Project $env:CARGO_TARGET_DIR)) }
    $flags = @()
    if ($env:CARGO_ENCODED_RUSTFLAGS) { $flags = @($env:CARGO_ENCODED_RUSTFLAGS.Split([char]31)) }
    elseif ($env:RUSTFLAGS) { $flags = @($env:RUSTFLAGS -split '\s+' | Where-Object { $_ }) }
    $flags += @('-C', 'target-feature=+crt-static')
    $env:CARGO_ENCODED_RUSTFLAGS = $flags -join [char]31
}

function Write-Utf8File([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}
