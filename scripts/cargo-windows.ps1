[CmdletBinding()]
param(
    [string]$PerlPath, [string]$PythonPath, [string]$VsDevCmdPath,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$CargoArgs
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\windows-build-common.ps1"
$settings = & "$PSScriptRoot\build-tls-windows.ps1" -PerlPath $PerlPath -PythonPath $PythonPath -VsDevCmdPath $VsDevCmdPath -PassThru
Set-WindowsCargoEnvironment $settings
$cargo = Resolve-BuildTool '' 'cargo.exe'
Push-Location $settings.Project
try {
    & $cargo @CargoArgs
    if ($LASTEXITCODE -ne 0) { throw "Cargo failed ($LASTEXITCODE)" }
} finally { Pop-Location }
