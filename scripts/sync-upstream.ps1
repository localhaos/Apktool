param(
    [string]$WorkDir = "work\Apktool",
    [string]$UpstreamUrl = "https://github.com/iBotPeaches/Apktool.git",
    [string]$UpstreamBranch = "main"
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
$FullWorkDir = Join-Path $RootDir $WorkDir

if (Test-Path $FullWorkDir) {
    Remove-Item -Recurse -Force $FullWorkDir
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $FullWorkDir) | Out-Null

git clone --depth 1 --branch $UpstreamBranch $UpstreamUrl $FullWorkDir
python (Join-Path $RootDir "scripts\apply-local-mods.py") $FullWorkDir

Push-Location $FullWorkDir
try {
    .\gradlew.bat --no-daemon build shadowJar
    Write-Host "`nBuilt jars:"
    Get-ChildItem "brut.apktool\apktool-cli\build\libs" -Filter "*.jar" | ForEach-Object { $_.FullName }
}
finally {
    Pop-Location
}
