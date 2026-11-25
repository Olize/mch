param(
    [Parameter(Mandatory)][string]$Binary,
    [Parameter(Mandatory)][string]$VolumeRoot
)
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $Binary).Path
$root = (Resolve-Path -LiteralPath $VolumeRoot).Path
$drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($root))
if ($drive.DriveFormat -ne 'exFAT') { throw 'An exFAT test volume is required.' }
$work = Join-Path $root ('mch-test-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
Push-Location -LiteralPath $work
try {
    [IO.File]::WriteAllText((Join-Path $work 'source'), 'copy payload')
    [IO.File]::WriteAllText((Join-Path $work 'existing'), 'preserve')
    & $exe -q source copied
    if ($LASTEXITCODE -ne 0 -or (Get-FileHash source).Hash -ne (Get-FileHash copied).Hash) {
        throw 'Copy or hash verification failed.'
    }
    & $exe -q source existing
    if ($LASTEXITCODE -eq 0 -or [IO.File]::ReadAllText((Join-Path $work 'existing')) -ne 'preserve') {
        throw 'An existing file was not preserved.'
    }
    & $exe -q --overwrite source existing
    if ($LASTEXITCODE -ne 0 -or (Get-FileHash source).Hash -ne (Get-FileHash existing).Hash) {
        throw 'Explicit overwrite failed.'
    }
    Write-Output 'MCH_WINDOWS_EXFAT_PASS'
} finally {
    Pop-Location
    Remove-Item -LiteralPath $work -Recurse -Force
}
