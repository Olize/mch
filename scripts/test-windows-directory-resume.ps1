# Borrow the existing 512 MiB CI fixture and force-stop the optimized directory copier.
param([Parameter(Mandatory)][string]$Binary,
      [Parameter(Mandatory)][string]$FixtureDirectory,
      [Parameter(Mandatory)][string]$LargeFile,
      [Parameter(Mandatory)][string]$ExpectedHash)
$ErrorActionPreference = 'Stop'
$src = Join-Path $FixtureDirectory 'tree-source'
$dst = Join-Path $FixtureDirectory 'tree-target'
$state = Join-Path $FixtureDirectory 'tree-state'
foreach ($path in @($src,$dst,$state)) { [void][IO.Directory]::CreateDirectory($path) }
[void][IO.Directory]::CreateDirectory((Join-Path $src 'nested\empty'))
[IO.File]::WriteAllText((Join-Path $src 'a-finished.txt'),'keep this completed file')
$large = 'z-large.bin'
Move-Item -LiteralPath $LargeFile -Destination (Join-Path $src $large)
$start = [Diagnostics.ProcessStartInfo]::new()
$start.UseShellExecute = $false
$start.RedirectStandardError = $true
$start.FileName = $Binary
$start.Arguments = '--resume-dir --progress always --progress-interval-ms 50 --resume-dir-state "'+$state+'" "'+$src+'" "'+$dst+'"'
$p = [Diagnostics.Process]::Start($start)
try {
    do {
        $read = $p.StandardError.ReadLineAsync()
        if (!$read.Wait(60000)) { throw 'Timeout waiting for directory copy progress' }
        $line = $read.Result
        if ($null -eq $line) { throw 'Directory copy exited before interruption' }
    } until ($line -match 'RESUME COPYING:.*\| [1-9][0-9]* B newly copied' -and (Test-Path -LiteralPath (Join-Path $dst 'nested\empty')))
    $p.Kill()
    $p.WaitForExit()
} finally {
    if (!$p.HasExited) { $p.Kill(); $p.WaitForExit() }
    $p.Dispose()
}
$finished = Join-Path $dst 'a-finished.txt'
if ([IO.File]::ReadAllText($finished) -ne 'keep this completed file' -or (Test-Path -LiteralPath (Join-Path $dst $large))) {
    throw 'Unexpected visible tree after process termination'
}
$partial = @(Get-ChildItem -Force -LiteralPath (Join-Path $state '.mch-winresume-work') -Filter '*.part')
if ($partial.Count -ne 1 -or $partial[0].Length -le 0 -or $partial[0].Length -ge 512MB) { throw 'Missing directory-job partial file' }
$reused = $partial[0].Length
$replay = @(& $Binary --resume-dir --progress never --resume-dir-state $state $src $dst)
if ($LASTEXITCODE -ne 0 -or $replay -notcontains "RESUME: $reused existing bytes compared and verified against source" -or
    !($replay -match 'RESUME-DIR VERIFIED .*a-finished\.txt$')) { throw 'Directory restart failed to reuse both the completed and the partial file' }
foreach ($root in @($src,$dst)) {
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root $large)).Hash -ne $ExpectedHash -or
        !(Test-Path -PathType Container -LiteralPath (Join-Path $root 'nested\empty'))) { throw 'Tree hash or empty directory mismatch' }
}
Write-Output "MCH_WINDOWS_DIRECTORY_KILL_RESUME_PASS reused=$reused total=536870912 sha256=$ExpectedHash"

$outside = Join-Path $FixtureDirectory 'junction-target'
[void][IO.Directory]::CreateDirectory($outside)
$junction = Join-Path $src 'unsupported-junction'
[void](New-Item -ItemType Junction -Path $junction -Target $outside)
try {
    & $Binary -q --resume-dir --resume-dir-state $state $src $dst
    if ($LASTEXITCODE -eq 0 -or (Test-Path -LiteralPath (Join-Path $dst 'unsupported-junction'))) { throw 'Source junction accepted' }
} finally {
    [IO.Directory]::Delete($junction)
}
Write-Output 'MCH_WINDOWS_DIRECTORY_JUNCTION_REFUSAL_PASS'
