param([string]$Binary,[string]$Root,[string]$Format)
$ErrorActionPreference = 'Stop'
$drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($Root))
if ($drive.DriveFormat -ne $Format) { throw "Unexpected volume format $($drive.DriveFormat)" }
$stamp = 'mch-' + [guid]::NewGuid().ToString('N')
$local = Join-Path $env:TEMP $stamp
[void][IO.Directory]::CreateDirectory($local)
foreach ($mode in @('copy','move')) {
    $name = "$stamp-$mode"
    $source = Join-Path $local $name
    $child = Join-Path $source 'nested'
    $target = Join-Path $Root $name
    if (Test-Path -LiteralPath $target) { throw 'Destination must be unused' }
    [void][IO.Directory]::CreateDirectory($child)
    $inputFile = Join-Path $child 'payload.txt'
    [IO.File]::WriteAllText($inputFile,"$Format $mode")
    $hash = (Get-FileHash $inputFile).Hash
    $flags = @('-q')
    if ($mode -eq 'move') { $flags += '--move' }
    $stderr = Join-Path $local 'stderr.txt'
    $p = Start-Process -Wait -PassThru -NoNewWindow -FilePath $Binary -ArgumentList ($flags + @('"' + $source + '"', $Root)) -RedirectStandardError $stderr
    if ($p.ExitCode -ne 0) {
        $message = (Get-Content -Raw -LiteralPath $stderr)
        throw "$Format directory $mode failed ($($p.ExitCode)): $message"
    }
    if ((Get-FileHash (Join-Path $target 'nested\payload.txt')).Hash -ne $hash) { throw 'Payload differs' }
    if ((Test-Path -LiteralPath $source) -ne ($mode -eq 'copy')) { throw 'Unexpected source retention' }
    Remove-Item -Recurse -Force -LiteralPath $target
    Write-Output "MCH_WINDOWS_$($Format.ToUpperInvariant())_DIRECTORY_$($mode.ToUpperInvariant())_PASS"
}
Remove-Item -Recurse -Force -LiteralPath $local
