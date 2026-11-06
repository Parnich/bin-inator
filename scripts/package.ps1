#requires -Version 5.1
<#
.SYNOPSIS
    Build and package the bin-inator Windows release.

.DESCRIPTION
    Builds both binaries in release mode and writes a self-contained ZIP to
    dist\bin-inator-<version>-<platform>.zip with the executables and docs.

.PARAMETER SkipBuild
    Package existing target\release binaries without rebuilding.

.PARAMETER OutputDir
    Destination directory for the ZIP. Defaults to <repo>\dist.
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [string]$OutputDir
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $root "Cargo.toml"
if (-not (Test-Path $manifest)) {
    throw "Cargo.toml not found at $manifest"
}

$versionLine = Select-String -Path $manifest -Pattern '^version = "(.+)"' | Select-Object -First 1
if (-not $versionLine) {
    throw "Could not read the package version from Cargo.toml"
}
$version = $versionLine.Matches[0].Groups[1].Value

$hostLine = rustc -vV | Select-String '^host: '
if (-not $hostLine) {
    throw "Could not determine the rustc host target"
}
$rustHost = $hostLine.Line.Substring(6).Trim()
$platform = switch -Wildcard ($rustHost) {
    "x86_64-*windows*" { "windows-x64" }
    "aarch64-*windows*" { "windows-arm64" }
    default { $rustHost }
}

Push-Location $root
$stage = $null
try {
    if (-not $SkipBuild) {
        Write-Host "Building release binaries..."
        cargo build --release --bins
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build --release --bins failed with exit code $LASTEXITCODE"
        }
    }

    $binaries = @("bin-inator.exe", "bin-inator-gui.exe")
    foreach ($binary in $binaries) {
        $path = Join-Path $root "target\release\$binary"
        if (-not (Test-Path $path)) {
            throw "Missing release binary: $path"
        }
    }

    if (-not $OutputDir) {
        $OutputDir = Join-Path $root "dist"
    }
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ("bin-inator-package-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $stage | Out-Null

    foreach ($binary in $binaries) {
        Copy-Item (Join-Path $root "target\release\$binary") (Join-Path $stage $binary)
    }
    Copy-Item (Join-Path $root "README.md") (Join-Path $stage "README.md")
    $format = Join-Path $root "docs\FORMAT.md"
    if (Test-Path $format) {
        New-Item -ItemType Directory -Path (Join-Path $stage "docs") | Out-Null
        Copy-Item $format (Join-Path $stage "docs\FORMAT.md")
    }

    $versionInfo = @(
        "bin-inator $version",
        "target: $rustHost",
        "platform: $platform",
        "built: $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    ) -join [Environment]::NewLine
    Set-Content -Path (Join-Path $stage "VERSION.txt") -Value $versionInfo -Encoding utf8

    $zipName = "bin-inator-$version-$platform.zip"
    $zipPath = Join-Path $OutputDir $zipName
    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
    }
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zipPath -CompressionLevel Optimal

    $size = (Get-Item $zipPath).Length
    $hash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ""
    Write-Host "Package: $zipPath"
    Write-Host ("Size:    {0:N1} MiB" -f ($size / 1MB))
    Write-Host "SHA-256: $hash"
}
finally {
    if ($stage -and (Test-Path $stage)) {
        Remove-Item $stage -Recurse -Force
    }
    Pop-Location
}
