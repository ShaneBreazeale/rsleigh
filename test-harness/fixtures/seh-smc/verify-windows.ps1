$ErrorActionPreference = 'Stop'
foreach ($variant in @('direct', 'indirect')) {
    $process = Start-Process -FilePath (Join-Path $PSScriptRoot "$variant.exe") -PassThru
    if (-not $process.WaitForExit(10000)) {
        $process.Kill()
        throw "$variant timed out"
    }
    if ($process.ExitCode -ne 42) {
        throw "$variant returned $($process.ExitCode), expected 42"
    }
    Write-Host "$variant passed: exit code 42"
}
