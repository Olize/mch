# Run in the x64 MSVC environment on the Windows 11 reference VM.
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
    [Parameter(Mandatory)][string]$Archive,
    [Parameter(Mandatory)][string]$Workspace,
    [Parameter(Mandatory)][string]$ExfatRoot,
    [string]$Fat32Root
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
if ([Environment]::OSVersion.Version.Build -lt 22000 -or ![Environment]::Is64BitProcess) {
    throw 'Windows 11 x64 is required.'
}
$toolchain = & rustc -vV
if ($LASTEXITCODE -ne 0 -or $toolchain -notcontains 'host: x86_64-pc-windows-msvc') { throw 'Expected x64 MSVC Rust host.' }
$tar = (Resolve-Path -LiteralPath $Archive).Path
if (Test-Path -LiteralPath $Workspace) { throw 'Use a new workspace for this run.' }
[void][IO.Directory]::CreateDirectory($Workspace)
Write-Output "MCH_SOURCE $Commit"
Write-Output ("MCH_ARCHIVE_SHA256 " + (Get-FileHash -LiteralPath $tar -Algorithm SHA256).Hash.ToLowerInvariant())
Write-Output "MCH_WINDOWS_BUILD $([Environment]::OSVersion.Version.Build)"
Write-Output 'MCH_HOST x86_64-pc-windows-msvc'
& tar.exe -xf $tar -C $Workspace
if ($LASTEXITCODE -ne 0) { throw 'Source extraction failed.' }
Push-Location -LiteralPath $Workspace
try {
    foreach ($stage in @(
        @{ Name = 'fmt'; Args = @('fmt','--all','--check') },
        @{ Name = 'clippy'; Args = @('clippy','--locked','--all-targets','--','-D','warnings') },
        @{ Name = 'test'; Args = @('test','--locked','--all-targets') },
        @{ Name = 'build'; Args = @('build','--release','--locked') }
    )) {
        $arguments = $stage.Args
        & cargo @arguments
        if ($LASTEXITCODE -ne 0) { throw ("Failed stage " + $stage.Name) }
        Write-Output ("MCH_RESULT " + $stage.Name + " 0")
    }
    $metadata = & cargo metadata --locked --offline --no-deps --format-version=1
    if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
    $out = ($metadata | ConvertFrom-Json).target_directory
    & .\scripts\check-windows-exfat.ps1 -Binary (Join-Path $out 'release\mch.exe') -VolumeRoot $ExfatRoot
    $directoryProbe = Join-Path $Workspace 'scripts\check-windows-directory-volumes.ps1'
    if (-not $Fat32Root) {
        $volumes = @(Get-Volume | Where-Object {$_.FileSystemLabel -eq 'MCHFAT32' -and $_.FileSystem -eq 'FAT32' -and $_.DriveLetter})
        if ($volumes.Count -ne 1) { throw 'Provide a disposable FAT32 drive using -Fat32Root or the MCHFAT32 label.' }
        $Fat32Root = $volumes[0].DriveLetter + ':\'
    }
    & $directoryProbe -Binary (Join-Path $out 'release\mch.exe') -Root ([IO.Path]::GetPathRoot($ExfatRoot)) -Format 'exFAT'
    & $directoryProbe -Binary (Join-Path $out 'release\mch.exe') -Root ([IO.Path]::GetPathRoot($Fat32Root)) -Format 'FAT32'
    Write-Output "MCH_WINDOWS_PASS"
} finally {
    Pop-Location
}
