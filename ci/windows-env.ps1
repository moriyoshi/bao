param(
  # Explicit override also permits an isolated developer-shell regression fixture.
  [string] $InstallationPath
)

$ErrorActionPreference = 'Stop'
# Import the chosen target's real VC toolset without replacing GitHub's shell
# environment wholesale (in particular GITHUB_*, secrets and runner identity).
if ($env:SUITE -notin @('windows-amd64', 'windows-arm64')) { throw 'Expected a Windows CI suite' }
$arch = if ($env:SUITE -eq 'windows-arm64') { 'arm64' } else { 'amd64' }
$component = if ($arch -eq 'arm64') { 'Microsoft.VisualStudio.Component.VC.Tools.ARM64' } else { 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' }
if (!$InstallationPath) {
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  $InstallationPath = & $vswhere -latest -products '*' -requires $component -property installationPath
  if ($LASTEXITCODE -ne 0 -or !$InstallationPath) { throw 'No installed MSVC toolset' }
}
# Invoke Microsoft's supported PowerShell entry point directly. A command string
# passed through PowerShell's native-argument binding to cmd.exe was re-quoted,
# turning the Program Files path into an invalid '""C:\Program' command.
$devshell = Join-Path $InstallationPath 'Common7/Tools/Launch-VsDevShell.ps1'
if (!(Test-Path -LiteralPath $devshell -PathType Leaf)) { throw 'Visual Studio Developer PowerShell is missing' }
& $devshell -SkipAutomaticLocation -Arch $arch -HostArch $arch
if (!$?) { throw 'VC environment setup failed' }
$allowed = @('PATH', 'INCLUDE', 'LIB', 'LIBPATH', 'VCToolsInstallDir', 'VCToolsVersion', 'WindowsSdkDir', 'WindowsSDKVersion')
foreach ($name in $allowed) {
  $value = [Environment]::GetEnvironmentVariable($name)
  if ($value) {
    "$name=$value" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
  }
}
