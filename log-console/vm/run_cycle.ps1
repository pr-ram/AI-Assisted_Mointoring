<#
  run_cycle.ps1  -  the job the scheduled task runs every 5 minutes:
     1. collect_events.ps1  -> latest_batch.json
     2. sender.py --mode snapshot -> console on the Mac (only NEW events are sent)
  Output is appended to cycle.log (rotated at 1 MB). Nothing is blocked or changed on the VM.
#>
param(
  [string]$Dir = "C:\SecurityTools",
  [Parameter(Mandatory = $true)][string]$Python,     # full path to python.exe
  [Parameter(Mandatory = $true)][string]$ConsoleUrl, # e.g. https://192.168.64.1:8443
  [string]$HostName = $env:COMPUTERNAME
)
$ErrorActionPreference = "Continue"
$logFile = Join-Path $Dir "cycle.log"
if ((Test-Path $logFile) -and (Get-Item $logFile).Length -gt 1MB) {
  Move-Item $logFile "$logFile.old" -Force
}
function Log($m) { Add-Content -Path $logFile -Value $m }

try {
  Log (& (Join-Path $Dir "collect_events.ps1") -OutFile (Join-Path $Dir "latest_batch.json") 2>&1 | Out-String).Trim()
} catch {
  Log ("{0} COLLECT FAILED: {1}" -f (Get-Date -Format s), $_.Exception.Message)
  exit 1
}

$out = & $Python (Join-Path $Dir "sender.py") `
  --url $ConsoleUrl --file (Join-Path $Dir "latest_batch.json") --host $HostName `
  --cafile (Join-Path $Dir "cert.pem") --mode snapshot 2>&1 | Out-String
Log ("{0} sender: {1}" -f (Get-Date -Format s), $out.Trim())
exit $LASTEXITCODE
