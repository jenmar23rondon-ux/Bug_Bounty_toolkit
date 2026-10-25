$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$port = if ($env:IDOR_LAB_PORT) { $env:IDOR_LAB_PORT } else { "8099" }
$python = (Get-Command python).Source
$priorPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = if ($priorPythonPath) { "$repoRoot$([IO.Path]::PathSeparator)$priorPythonPath" } else { $repoRoot }
$server = Start-Process -FilePath $python -ArgumentList @("-m", "bugbounty_toolkit.idor_lab_server", "--host", "127.0.0.1", "--port", $port) -WorkingDirectory $repoRoot -WindowStyle Hidden -PassThru
try {
    Wait-Process -Id $server.Id
} finally {
    $server.Refresh()
    if (-not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
        Wait-Process -Id $server.Id -ErrorAction SilentlyContinue
    }
    $env:PYTHONPATH = $priorPythonPath
}
