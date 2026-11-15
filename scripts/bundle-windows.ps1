[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$WintunRoot,
    [string]$PerlPath, [string]$PythonPath, [string]$VsDevCmdPath,
    [string]$OutputDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\windows-build-common.ps1"
# Windows PowerShell 5 does not reliably capture GUI-subsystem executables
# with the native-call operator. Supply real pipes and wait for the exit code.
function Invoke-ApplicationCapture([string]$Path, [string]$Arguments) {
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.FileName = $Path
    $process.StartInfo.Arguments = $Arguments
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $process.StartInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    try {
        if (-not $process.Start()) { throw 'Could not start application check' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) {
            $process.Kill()
            throw 'Application check timed out'
        }
        $output = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "Application check failed ($($process.ExitCode)): $errorText" }
        return $output.TrimEnd([char[]]"`r`n")
    } finally { $process.Dispose() }
}
$settings = & "$PSScriptRoot\build-tls-windows.ps1" -PerlPath $PerlPath -PythonPath $PythonPath -VsDevCmdPath $VsDevCmdPath -PassThru
Set-WindowsCargoEnvironment $settings
$cargo = Resolve-BuildTool '' 'cargo.exe'
Push-Location $settings.Project
try {
    & $cargo build --release --locked --target $settings.Target -p sslray
    if ($LASTEXITCODE -ne 0) { throw "Cargo release build failed ($LASTEXITCODE)" }
} finally { Pop-Location }
$exe = Join-Path $env:CARGO_TARGET_DIR "$($settings.Target)\release\sslray.exe"
$imports = @(Assert-StaticWindowsBinary $exe)
$workspaceText = Get-Content -LiteralPath (Join-Path $settings.Project 'Cargo.toml') -Raw
$packageSection = [regex]::Match($workspaceText, '(?ms)^\[workspace\.package\]\s*(?<body>.*?)(?=^\[|\z)').Groups['body'].Value
$version = [regex]::Match($packageSection, '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
if ($version -notmatch '^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$') { throw 'Could not read workspace release version' }
$cliVersion = Invoke-ApplicationCapture $exe '--version'
if ("$cliVersion" -ne "sslray $version") { throw 'CLI/workspace version mismatch' }
$capabilitiesText = Invoke-ApplicationCapture $exe 'capabilities'
$capabilities = ($capabilitiesText -join "`n") | ConvertFrom-Json
if (-not $capabilities.gm_tls13 -or $capabilities.backend -notlike 'OpenSSL *') { throw 'Static backend/GM capability check failed' }
$wintun = Join-Path $WintunRoot 'bin\amd64\wintun.dll'
$wintunLicense = Join-Path $WintunRoot 'LICENSE.txt'
$wintunHash = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
$licenseHash = '183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2'
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $wintun).Hash.ToLowerInvariant() -ne $wintunHash) { throw 'Expected the unchanged official Wintun 0.14.1 AMD64 DLL' }
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $wintunLicense).Hash.ToLowerInvariant() -ne $licenseHash) { throw 'Wintun original license bytes do not match the verified archive' }
if ((Get-PeMachine $wintun) -ne 0x8664) { throw 'Wintun DLL architecture mismatch' }
$wintunSignature = Get-AuthenticodeSignature -LiteralPath $wintun
if ($wintunSignature.Status -ne 'Valid') { throw "Official Wintun signature did not validate: $($wintunSignature.Status)" }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $settings.Project 'dist' }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$name = "SSLRay-$version-windows-x64"
$destination = Join-Path $OutputDirectory $name
$zip = Join-Path $OutputDirectory "$name.zip"
if ((Test-Path -LiteralPath $destination) -or (Test-Path -LiteralPath $zip)) { throw 'Versioned output already exists; choose an empty output directory' }
$stage = Join-Path $settings.Project ("work\windows-release-stage-" + [Guid]::NewGuid().ToString('N'))
$package = Join-Path $stage $name
$stagedZip = Join-Path $stage "$name.zip"
New-Item -ItemType Directory -Path $package | Out-Null
try {
    Copy-Item -LiteralPath $exe -Destination (Join-Path $package 'sslray.exe')
    Copy-Item -LiteralPath $wintun -Destination (Join-Path $package 'wintun.dll')
    Copy-Item -LiteralPath $wintunLicense -Destination (Join-Path $package 'WINTUN-LICENSE.txt')
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $package 'wintun.dll')).Hash.ToLowerInvariant() -ne $wintunHash) { throw 'Copied Wintun DLL hash mismatch' }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $package 'WINTUN-LICENSE.txt')).Hash.ToLowerInvariant() -ne $licenseHash) { throw 'Copied Wintun license hash mismatch' }
    Copy-Item -LiteralPath (Join-Path $settings.Project 'LICENSE') -Destination (Join-Path $package 'LICENSE')
    Copy-Item -LiteralPath (Join-Path $settings.Project 'COPYRIGHT') -Destination (Join-Path $package 'COPYRIGHT')
    Copy-Item -LiteralPath (Join-Path $settings.Project 'LICENSE-WINTUN-EXCEPTION') -Destination (Join-Path $package 'LICENSE-WINTUN-EXCEPTION')
    $notices = Join-Path $package 'ThirdPartyLicenses'
    & $settings.Python "$PSScriptRoot\collect-licenses.py" --output $notices --binary $exe --tls-source $settings.Source
    if ($LASTEXITCODE -ne 0) { throw 'Third-party notice collection failed' }
    New-Item -ItemType Directory -Path (Join-Path $notices 'Wintun') | Out-Null
    Copy-Item -LiteralPath $wintunLicense -Destination (Join-Path $notices 'Wintun\LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $settings.Project 'third_party\wintun\README.md') -Destination (Join-Path $notices 'Wintun\UPSTREAM.md')
    $noticeIndex = Join-Path $notices 'INDEX.json'
    $index = Get-Content -LiteralPath $noticeIndex -Raw | ConvertFrom-Json
    $index.components += [pscustomobject]@{ name = 'Wintun prebuilt binaries'; version = '0.14.1'; dll_sha256 = $wintunHash; files = @('Wintun/LICENSE.txt','Wintun/UPSTREAM.md') }
    Write-Utf8File $noticeIndex ($index | ConvertTo-Json -Depth 12)
    $exeSignature = Get-AuthenticodeSignature -LiteralPath $exe
    $buildInfo = [ordered]@{
        Version = "$version"; Architecture = 'x64'; Target = $settings.Target; Capabilities = $capabilities
        OpenSSL = (Get-Content -LiteralPath (Join-Path $settings.Root 'build-settings.json') -Raw | ConvertFrom-Json)
        RustFlags = @($env:CARGO_ENCODED_RUSTFLAGS.Split([char]31)); DynamicImports = $imports
        ExecutableSignatureStatus = "$($exeSignature.Status)"; ScriptSignsExecutable = $false
        WintunVersion = '0.14.1'; WintunSHA256 = $wintunHash; WintunSignatureStatus = "$($wintunSignature.Status)"
    }
    Write-Utf8File (Join-Path $package 'build-info.json') ($buildInfo | ConvertTo-Json -Depth 14)
    Write-Utf8File (Join-Path $package 'README.txt') @"
SSLRay $version - Windows x64
Keep sslray.exe and the original wintun.dll in the same protected directory.
This packager does not sign sslray.exe. Actual Authenticode status: $($exeSignature.Status).
Wintun 0.14.1 AMD64 is hash-checked and its signature was Valid on this machine.
The application requests elevation through Windows UAC only when connecting.
OpenSSL is static, GM-enabled, compiled without assembly and with static CRT.
ThirdPartyLicenses/INDEX.json records the exact local notice collection scope and gaps.
This build/packaging check does not itself test a VPN, UAC, routes or Wintun adapter creation.
"@
    $sums = @(Get-ChildItem -LiteralPath $package -File -Recurse | Sort-Object FullName | ForEach-Object {
        '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant(), $_.FullName.Substring($package.Length + 1).Replace('\','/')
    })
    Write-Utf8File (Join-Path $package 'SHA256SUMS.txt') (($sums -join "`n") + "`n")
    Compress-Archive -LiteralPath $package -DestinationPath $stagedZip -CompressionLevel Optimal
    $verify = Join-Path $stage 'verify'
    Expand-Archive -LiteralPath $stagedZip -DestinationPath $verify
    foreach ($file in Get-ChildItem -LiteralPath $package -File -Recurse) {
        $copy = Join-Path (Join-Path $verify $name) $file.FullName.Substring($package.Length + 1)
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $copy).Hash) { throw 'ZIP extraction content mismatch' }
    }
    Move-Item -LiteralPath $package -Destination $destination
    Move-Item -LiteralPath $stagedZip -Destination $zip
    $zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
    Write-Utf8File (Join-Path $OutputDirectory "$name.sha256") ("$zipHash  $name.zip`n")
    Write-Host "Built $destination"
    Write-Host "ZIP $zip"
    Write-Host "SHA256 $zipHash"
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
