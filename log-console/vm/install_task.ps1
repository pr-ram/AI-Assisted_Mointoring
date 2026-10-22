<#
  install_task.ps1  -  run ONCE in an ADMINISTRATOR Windows PowerShell on the VM.
  Creates the scheduled task "LabEventSender" that runs run_cycle.ps1 every 5 minutes.

  Before running: C:\SecurityTools must contain
     collect_events.ps1, run_cycle.ps1, sender.py, cert.pem, sender.env (with CONSOLE_TOKEN=...)

  Example:
     powershell -ExecutionPolicy Bypass -File C:\SecurityTools\install_task.ps1 -ConsoleUrl https://192.168.64.1:8443
#>
param(
  [Parameter(Mandatory = $true)][string]$ConsoleUrl,
  [string]$Dir = "C:\SecurityTools",
  [int]$EveryMinutes = 5
)
$ErrorActionPreference = "Stop"
foreach ($f in "collect_events.ps1","run_cycle.ps1","sender.py","cert.pem","sender.env") {
  if (-not (Test-Path (Join-Path $Dir $f))) { throw "Missing $Dir\$f" }
}
$py = (Get-Command python -ErrorAction Stop).Source
if ($py -like "*WindowsApps*") { throw "That python.exe is the Microsoft Store stub. Install Python from python.org and retry." }
Write-Host "Using Python: $py"

# Only Administrators and SYSTEM may read the token file
icacls (Join-Path $Dir "sender.env") /inheritance:r /grant:r "Administrators:(R,W)" "SYSTEM:(R,W)" | Out-Null

$arg = "-NoProfile -ExecutionPolicy Bypass -File `"$Dir\run_cycle.ps1`" -Dir `"$Dir`" -Python `"$py`" -ConsoleUrl `"$ConsoleUrl`""
$action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg -WorkingDirectory $Dir
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
           -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
             -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "LabEventSender" -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "Task LabEventSender created: runs every $EveryMinutes minutes as SYSTEM."
Write-Host "Test now:  Start-ScheduledTask -TaskName LabEventSender ; then:  Get-Content $Dir\cycle.log -Tail 5"
Write-Host "Remove:    Unregister-ScheduledTask -TaskName LabEventSender -Confirm:`$false"
