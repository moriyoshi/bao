$ErrorActionPreference = 'Stop'
# Native LLVM-MinGW supplies a matched GNU-ABI Clang producer and C++/unwind DLLs.
# Hashes are the published GitHub release asset SHA-256 digests for 20261104.
$arch = switch ($env:SUITE) {
  'windows-amd64' { 'x86_64' }
  'windows-arm64' { 'aarch64' }
  default { throw 'Expected a Windows suite' }
}
$hash = if ($arch -eq 'aarch64') {
  '7d7f8387a8706639b0b47a629d6e23f8b3ef9acce67e9832b8cd4c5bb2816eab'
} else {
  '552191b5754c49a5a20723276a6fc56541ea1922c4c50b7b669022333fc1b40f'
}
$name = "llvm-mingw-20261104-ucrt-$arch"
$archive = Join-Path $env:RUNNER_TEMP "$name.zip"
$destination = Join-Path $env:RUNNER_TEMP 'bao-llvm-mingw'
Invoke-WebRequest "https://github.com/mstorsjo/llvm-mingw/releases/download/20261104/$name.zip" -OutFile $archive
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) {
  throw 'LLVM-MinGW archive integrity check failed'
}
Expand-Archive -LiteralPath $archive -DestinationPath $destination
$install = Join-Path $destination $name
if (!(Test-Path -LiteralPath (Join-Path $install 'bin/clang.exe'))) { throw 'LLVM-MinGW compiler missing' }
"BAO_LLVM_MINGW=$install" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
