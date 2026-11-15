[CmdletBinding()]
param([string]$PerlPath, [string]$PythonPath, [string]$VsDevCmdPath, [switch]$PassThru)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\windows-build-common.ps1"
$settings = Get-WindowsBuildSettings $PerlPath $PythonPath $VsDevCmdPath
$source = $settings.Source
if (-not (Test-Path -LiteralPath (Join-Path $source 'Configure') -PathType Leaf)) {
    throw 'Missing OpenSSL submodule. Run manually: git -c core.autocrlf=false submodule update --init third_party/openssl'
}
$revision = & $settings.Python "$PSScriptRoot\verify-openssl-windows.py" $source
if ($LASTEXITCODE -ne 0) { throw 'OpenSSL source pin verification failed' }
$options = @('VC-WIN64A', 'no-shared', 'no-module', 'no-tests', 'no-asm', 'enable-static-vcruntime', 'enable-sm2', 'enable-sm3', 'enable-sm4')
$configuration = [ordered]@{
    Revision = "$revision"; Target = $settings.Target; Options = $options
    Compiler = $settings.Compiler; CompilerVersion = $settings.CompilerVersion
    VCToolsVersion = $settings.VCToolsVersion; WindowsSDKVersion = $settings.WindowsSDKVersion
    Perl = $settings.Perl; PerlVersion = $settings.PerlVersion
    BuildScript = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash
    BuildCommon = (Get-FileHash -Algorithm SHA256 -LiteralPath "$PSScriptRoot\windows-build-common.ps1").Hash
    CL = "$env:CL"; ExtraCL = "$env:_CL_"; CFLAGS = "$env:CFLAGS"; CPPFLAGS = "$env:CPPFLAGS"; LDFLAGS = "$env:LDFLAGS"
}
$fingerprint = $configuration | ConvertTo-Json -Depth 8 -Compress
$prefix = Join-Path $settings.Root 'install'
$manifest = Join-Path $settings.Root 'build-settings.json'
$artifacts = @('lib\libssl.lib', 'lib\libcrypto.lib', 'bin\openssl.exe')
$reuse = $false
if (Test-Path -LiteralPath $manifest -PathType Leaf) {
    $cached = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    $reuse = $cached.Fingerprint -eq $fingerprint
    foreach ($artifact in $artifacts) {
        $path = Join-Path $prefix $artifact
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $reuse = $false; break }
        $property = $cached.Artifacts.PSObject.Properties[$artifact]
        if (-not $property -or $property.Value -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash) { $reuse = $false; break }
    }
}
if (-not $reuse) {
    $build = Join-Path $settings.Root 'build'
    New-Item -ItemType Directory -Force -Path $settings.Root | Out-Null
    # Only fixed generated children of this project's cache are removed.
    foreach ($directory in @($build, $prefix)) { if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force } }
    New-Item -ItemType Directory -Path $build | Out-Null
    Push-Location $build
    try {
        Write-Host 'Configuring pinned OpenSSL: native MSVC x64, static CRT, no assembly, GM enabled'
        Invoke-BuildStep $settings.Perl (@((Join-Path $source 'Configure')) + $options + @("--prefix=$prefix", '--libdir=lib', "--openssldir=$prefix\ssl")) (Join-Path $settings.Root 'configure.log')
        Write-Host 'Building OpenSSL (nmake, logs in work/openssl-windows-x64-static-noasm)'
        Invoke-BuildStep 'nmake.exe' @('/nologo', 'build_sw') (Join-Path $settings.Root 'build.log')
        Invoke-BuildStep 'nmake.exe' @('/nologo', 'install_sw') (Join-Path $settings.Root 'install.log')
    } finally { Pop-Location }
}
$openssl = Join-Path $prefix 'bin\openssl.exe'
$imports = @(Assert-StaticWindowsBinary $openssl)
$backend = & $openssl version
if ($LASTEXITCODE -ne 0) { throw 'Could not run the native OpenSSL backend' }
$ciphers = & $openssl ciphers -s -tls1_3 -ciphersuites 'TLS_SM4_GCM_SM3:TLS_SM4_CCM_SM3'
if ($LASTEXITCODE -ne 0 -or "$ciphers" -notmatch 'TLS_SM4_GCM_SM3' -or "$ciphers" -notmatch 'TLS_SM4_CCM_SM3') { throw 'GM TLS 1.3 cipher validation failed' }
$verifiedAfter = & $settings.Python "$PSScriptRoot\verify-openssl-windows.py" $source
if ($LASTEXITCODE -ne 0 -or "$verifiedAfter" -ne "$revision") { throw 'OpenSSL source changed during the build' }
$hashes = [ordered]@{}
foreach ($artifact in $artifacts) { $hashes[$artifact] = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $prefix $artifact)).Hash }
$record = [ordered]@{ Fingerprint = $fingerprint; Configuration = $configuration; Artifacts = $hashes; Backend = "$backend"; GmCiphers = "$ciphers"; DynamicImports = $imports }
Write-Utf8File $manifest ($record | ConvertTo-Json -Depth 10)
if ($reuse) { Write-Host "Reusing verified static OpenSSL: $prefix" } else { Write-Host "Built verified static OpenSSL: $prefix" }
if ($PassThru) { return $settings }
