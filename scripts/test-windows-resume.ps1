# Exercise an actual terminated optimized process using native NTFS and disposable media.
param([Parameter(Mandatory)][string]$Binary,
      [Parameter(Mandatory)][string]$ExfatRoot,
      [Parameter(Mandatory)][string]$Fat32Root)
$ErrorActionPreference = 'Stop'
$dir = Join-Path ([IO.Path]::GetTempPath()) ('mch-ntfs-resume-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($dir)
$source = Join-Path $dir 'source.bin'
$target = Join-Path $dir 'result.bin'
$process = $null
try {
    $chunk = [byte[]]::new(1MB)
    [Random]::new(42).NextBytes($chunk)
    $file = [IO.File]::Create($source)
    try {
        for ($i=0; $i -lt 512; $i++) {
            $chunk[0] = $i % 251
            $file.Write($chunk,0,$chunk.Length)
        }
        $file.Flush($true)
    } finally { $file.Dispose() }
    $expected = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Binary
    $start.UseShellExecute = $false
    $start.RedirectStandardError = $true
    $start.Arguments = '--resume --progress always --progress-interval-ms 50 "' + $source + '" "' + $target + '"'
    $process = [Diagnostics.Process]::Start($start)
    do {
        $read = $process.StandardError.ReadLineAsync()
        if (!$read.Wait(30000)) { throw 'Timed out waiting for native copy progress' }
        $line = $read.Result
        if ($null -eq $line) { throw 'Copy ended before an interruption could be observed' }
    } until ($line -match 'RESUME COPYING:.*\| ([1-9][0-9]*) B newly copied')
    $process.Kill()
    $process.WaitForExit()
    if (Test-Path -LiteralPath $target) { throw 'Partial target was published' }
    $part = @(Get-ChildItem -Force -LiteralPath $dir -Filter '.mch-winresume-*.part')
    if ($part.Count -ne 1 -or $part[0].Length -le 0 -or $part[0].Length -ge 512MB) { throw 'Expected a genuinely partial file' }
    $size = $part[0].Length
    $replay = @(& $Binary --resume --progress never $source $target)
    if ($LASTEXITCODE -ne 0 -or $replay -notcontains "RESUME: $size existing bytes compared and verified against source") { throw 'Restart failed to reuse the saved prefix' }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash -ne $expected -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash -ne $expected) { throw 'Final SHA-256 differs' }
    if (@(Get-ChildItem -Force -LiteralPath $dir -Filter '.mch-winresume-*').Count) { throw 'Completed state remained' }
    Write-Output "MCH_WINDOWS_NTFS_KILL_RESUME_PASS reused=$size total=536870912 sha256=$expected"
    foreach ($volume in @($ExfatRoot,$Fat32Root)) {
        $leaf = 'mch-resume-probe-' + [guid]::NewGuid().ToString('N')
        $fixture = New-Item -ItemType Directory -Path (Join-Path $volume $leaf)
        try {
            $dst = Join-Path $fixture.FullName 'target'
            foreach ($options in @(@('--resume'),@('--resume','--dry-run'))) {
                & $Binary -q @options $source $dst
                if ($LASTEXITCODE -eq 0 -or @(Get-ChildItem -Force -LiteralPath $fixture.FullName).Count) { throw 'Unsupported volume accepted during resume preflight' }
            }
            $tree = Join-Path $dir 'unsupported-tree'
            $jobState = Join-Path $dir 'unsupported-state'
            [void][IO.Directory]::CreateDirectory($tree)
            [void][IO.Directory]::CreateDirectory($jobState)
            & $Binary -q --resume-dir --resume-dir-state $jobState $tree $fixture.FullName
            if ($LASTEXITCODE -eq 0 -or @(Get-ChildItem -Force -LiteralPath $fixture.FullName).Count -or
                @(Get-ChildItem -Force -LiteralPath $jobState).Count) { throw 'Directory job accepted an unsupported volume or wrote state' }
        } finally { Remove-Item -LiteralPath $fixture.FullName -Force -Recurse }
    }
    Write-Output 'MCH_WINDOWS_RESUME_REJECT_FAT32_EXFAT_PASS'
    & (Join-Path $PSScriptRoot 'test-windows-directory-resume.ps1') -Binary $Binary -FixtureDirectory $dir -LargeFile $source -ExpectedHash $expected
} finally {
    if ($null -ne $process) {
        if (!$process.HasExited) { $process.Kill(); $process.WaitForExit() }
        $process.Dispose()
    }
    Remove-Item -LiteralPath $dir -Force -Recurse
}
