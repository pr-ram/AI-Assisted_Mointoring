<#
  collect_events.ps1  -  runs on the Windows VM (Windows PowerShell 5.1).
  Reads recent Sysmon events (IDs 1,3,11,13,22) and writes them to latest_batch.json
  as ONE JSON array, UTF-8 without BOM, replaced atomically. READ-ONLY: it changes nothing else.

  Each run looks back $LookbackMinutes (default 12) which is deliberately MORE than the
  5-minute schedule: overlap is harmless because sender.py (--mode snapshot) only sends events
  it has not sent before, and a missed run loses nothing.
#>
param(
  [string]$OutFile = "C:\SecurityTools\latest_batch.json",
  [int]$LookbackMinutes = 12,
  [int[]]$EventIds = @(1,3,11,13,22),
  [int]$MaxEvents = 2000
)
$ErrorActionPreference = "Stop"
$log = "Microsoft-Windows-Sysmon/Operational"
$since = (Get-Date).AddMinutes(-$LookbackMinutes)

$events = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $EventIds; StartTime = $since } `
            -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)   # "no events" is not an error

$rows = New-Object System.Collections.Generic.List[object]
foreach ($e in ($events | Sort-Object RecordId)) {
  $row = [ordered]@{
    Timestamp = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    EventID   = [int]$e.Id
    RecordId  = [int64]$e.RecordId
    Computer  = $e.MachineName
  }
  $xml = [xml]$e.ToXml()
  foreach ($d in $xml.Event.EventData.Data) {
    $v = [string]$d.'#text'
    if ($v.Length -gt 4000) { $v = $v.Substring(0, 4000) }
    if ($d.Name -and $v -ne "") { $row[$d.Name] = $v }
  }
  $rows.Add([pscustomobject]$row)
}

# Always an array, even for 0 or 1 events (PowerShell 5.1 would otherwise unwrap it)
if ($rows.Count -eq 0) { $json = "[]" }
else { $json = ConvertTo-Json -InputObject @($rows.ToArray()) -Depth 4 -Compress }

$dir = Split-Path $OutFile -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
$tmp = "$OutFile.tmp"
[System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))  # no BOM
Move-Item -Path $tmp -Destination $OutFile -Force
Write-Output ("{0} wrote {1} events to {2}" -f (Get-Date -Format s), $rows.Count, $OutFile)
