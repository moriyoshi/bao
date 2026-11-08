$ErrorActionPreference = 'Stop'
# No Visual Studio or Pester dependency: exercise the actual initialization
# script against a developer-shell fixture in a realistic path with spaces.
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('bao vc env ' + [guid]::NewGuid())
$install = Join-Path $fixture 'Program Files (fixture)/Microsoft Visual Studio/Build Tools'
$tools = Join-Path $install 'Common7/Tools'
$saved = @{}
foreach ($name in @('SUITE', 'GITHUB_ENV', 'PATH', 'INCLUDE', 'BAO_VC_UNAPPROVED')) {
  $saved[$name] = [Environment]::GetEnvironmentVariable($name)
}
try {
  New-Item -ItemType Directory -Path $tools -Force | Out-Null
  $shellPath = Join-Path $tools 'Launch-VsDevShell.ps1'
  @'
param([switch]$SkipAutomaticLocation, [string]$Arch, [string]$HostArch)
$expected = if ($env:SUITE -eq 'windows-arm64') { 'arm64' } else { 'amd64' }
if (!$SkipAutomaticLocation -or $Arch -ne $expected -or $HostArch -ne $expected) {
  throw 'Wrong developer-shell arguments'
}
$env:INCLUDE = "fixture include $Arch"
$env:PATH = "$env:PATH;fixture tools $Arch"
$env:BAO_VC_UNAPPROVED = 'must not be exported'
'@ | Set-Content -LiteralPath $shellPath
  foreach ($suite in @('windows-amd64', 'windows-arm64')) {
    $env:SUITE = $suite
    $env:GITHUB_ENV = Join-Path $fixture "$suite.env"
    $before = (Get-Location).Path
    & "$PSScriptRoot/windows-env.ps1" -InstallationPath $install
    $content = Get-Content -LiteralPath $env:GITHUB_ENV
    $arch = if ($suite -eq 'windows-arm64') { 'arm64' } else { 'amd64' }
    if ($content -notcontains "INCLUDE=fixture include $arch" -or
        !($content | Where-Object { $_ -like "PATH=*;fixture tools $arch" }) -or
        ($content | Where-Object { $_ -notmatch '^(PATH|INCLUDE|LIB|LIBPATH|VCToolsInstallDir|VCToolsVersion|WindowsSdkDir|WindowsSDKVersion)=' }) -or
        (Get-Location).Path -ne $before) {
      throw "Developer-shell initialization/export failed for $suite"
    }
  }
  # A failed setup must stop before appending any environment for the next step.
  "throw 'expected developer-shell failure'" | Set-Content -LiteralPath $shellPath
  $env:GITHUB_ENV = Join-Path $fixture 'must-not-exist.env'
  $failed = $false
  try { & "$PSScriptRoot/windows-env.ps1" -InstallationPath $install } catch {
    if ($_.Exception.Message -notlike '*expected developer-shell failure*') { throw }
    $failed = $true
  }
  if (!$failed -or (Test-Path -LiteralPath $env:GITHUB_ENV)) { throw 'Failed setup exported an environment' }
  Write-Output 'PASS: developer-shell paths with spaces, amd64/ARM64 arguments, allowed exports and failed-setup control'
} finally {
  foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
