# AI-Assisted Endpoint Log Triage (proof of concept)

A small tool that uses AI to watch a home Windows computer for suspicious activity and explains any problem in plain, everyday language.

```
Windows VM (stands in for a home computer)            Mac
┌──────────────────────────────────────┐   manual    ┌──────────────────────────────────────────┐
│ 1 Sysmon records activity            │    copy     │ 3 Mask      names -> tokens, leak check   │
│ 2 collect_events.ps1 -> latest_batch │ ──────────► │ 4 Ask Claude  masked events + fixed prompt│
└──────────────────────────────────────┘             │ 5 Verify    structure + grounding (Python)│
                                                     │ 6 Email     plain language, real names    │
                                                     └──────────────────────────────────────────┘
```

Course project (INFS 680, Option B). **Lab use only.** The tool watches and alerts; it never blocks, deletes or changes anything.

## What it does

1. **Collect.** A PowerShell script reads Sysmon events 1 (process create), 3 (network connect), 11 (file create), 13 (registry value set) and 22 (DNS query). It takes only events newer than the previous run, drops its own noise and Windows-update noise, and writes one JSON file.
2. **Copy.** The JSON file is copied manually from the VM to the Mac.
3. **Mask.** `mask_events.py` replaces user names, device names, domains, IP addresses and GUIDs with stable tokens (`USER_1`, `DEVICE_1`, `DOMAIN_1`, `INTERNAL_IP_1` ...). Repeated events are merged with a count. A leak check stops the run if a real value is still present.
4. **Ask Claude.** The masked events are sent to Claude together with a fixed prompt (see `SYSTEM_PROMPT` in `pipeline.py`). Claude returns a verdict (normal or abnormal) and findings with a title, severity, reason and cited event ids.
5. **Verify.** `pipeline.verify()` and `grounding.py` check the answer against the masked events.
6. **Email.** If a finding passes the severity threshold, `poc.py` writes a plain-language email, restores the real names from a local map, and sends it through Gmail SMTP.

Only masked events ever leave the Mac. The token-to-real-name map stays on the Mac.

## Requirements

| Where | What |
| --- | --- |
| Windows VM | Windows 10/11, Sysmon (tested with 15.22), Windows PowerShell 5.1, an Administrator account |
| Mac | Python 3.10+ (standard library only, no pip packages), [Claude Code](https://claude.com/claude-code) installed and signed in with a Claude account |
| Email (optional) | A Gmail account with 2-Step Verification and an [App password](https://myaccount.google.com/apppasswords) |

## Files

| File | Purpose |
| --- | --- |
| `vm/collect_events.ps1` | Runs on the VM. Reads new Sysmon events and writes `latest_batch.json` |
| `poc.py` | Runs the whole chain on the Mac and builds the email |
| `mask_events.py` | Masks names, merges repeats, runs the leak check |
| `pipeline.py` | Calls Claude (with the fixed prompt) and runs `verify()` |
| `grounding.py` | Checks that details in each finding appear in the events it cites |
| `config.env.example` | Settings template. Copy to `config.env` |
| `README.md` | This file |

`evaluate.py`, `rules_baseline.py` and `scenarios.json` are an optional, separate benchmark of synthetic cases. They are not used by `poc.py`, and the results in the report do not depend on them.

## Setup

### 1. Sysmon on the VM

The tool can only judge what Sysmon records. A default or restrictive configuration may hide events. In testing, the original configuration logged network connections only on ports 80 and 443 and had no file or registry rules, so those scenarios produced no events until the configuration was changed.

Save this as `C:\Tools\Sysmon\sysmon_lab.xml` (adjust the folder to where your `Sysmon64.exe` is). It logs all processes, network connections and DNS queries, file creation in four folders, and registry writes under the Run keys:

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <RuleGroup name="proc" groupRelation="or"><ProcessCreate onmatch="exclude"/></RuleGroup>
    <RuleGroup name="net" groupRelation="or"><NetworkConnect onmatch="exclude"/></RuleGroup>
    <RuleGroup name="dns" groupRelation="or"><DnsQuery onmatch="exclude"/></RuleGroup>
    <RuleGroup name="file" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\Downloads\</TargetFilename>
        <TargetFilename condition="contains">\Start Menu\Programs\Startup\</TargetFilename>
        <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
        <TargetFilename condition="contains">\Users\Public\</TargetFilename>
      </FileCreate>
    </RuleGroup>
    <RuleGroup name="reg" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Apply it in an elevated PowerShell, then confirm it loaded:

```powershell
& "C:\Tools\Sysmon\Sysmon64.exe" -c "C:\Tools\Sysmon\sysmon_lab.xml"
& "C:\Tools\Sysmon\Sysmon64.exe" -c
```

To go back to your old configuration, run the same command with your old XML file. If Sysmon reports a schema-version error, change the first line to the version it asks for.

To see which event types are being logged:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=(Get-Date).AddHours(-24)} | Group-Object Id | Sort-Object { [int]$_.Name } | Select-Object Name, Count
```

### 2. Collector on the VM

Create `C:\SecurityTools\` and put `vm/collect_events.ps1` in it.

### 3. Mac

```bash
cd ~/log-console                     # the folder holding poc.py
cp config.env.example config.env
chmod 600 config.env                 # then edit config.env
claude                               # run once and sign in with your Claude account
```

Edit `config.env`:

| Setting | Meaning |
| --- | --- |
| `CLAUDE_BACKEND=cli` | Use the Claude Code command line (your Claude plan, no API key) |
| `CLAUDE_MODEL=haiku` | Model alias |
| `MIN_SEVERITY=medium` | Lowest severity that triggers an email: `low`, `medium` or `high` |
| `STRICT_GROUNDING=0` | `1` drops findings whose details are not in the cited events; `0` keeps them with a caution |
| `SENSITIVE_TERMS=` | Extra words to hide (family names, school, street), comma separated |
| `ALERT_UNMASK=1` | `1` shows real names in the email; `0` keeps tokens |
| `SMTP_*`, `MAIL_FROM`, `MAIL_TO` | Gmail settings. `SMTP_PASSWORD` is the 16-letter App password, not your Gmail password |

**Never put `config.env`, passwords or tokens in git, chat or screenshots.**

## Run it

### 1. Collect on the VM

In PowerShell as Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File C:\SecurityTools\collect_events.ps1
```

It collects events newer than its previous run (the first run covers the last 24 hours), prints `read N new events, wrote M ... (filtered: self=X, update=Y)`, and writes `C:\SecurityTools\latest_batch.json`.

| Want | Do this |
| --- | --- |
| Only the last 15 minutes | Add `-LookbackMinutes 15` |
| Start over | Delete `C:\SecurityTools\collector_state.json` |

### 2. Copy to the Mac

Copy `latest_batch.json` to `~/log-console/` by hand (shared folder, drag and drop, or `scp`).

### 3. Look at the masked data first

Nothing is sent to Claude in this step:

```bash
python3 poc.py latest_batch.json --no-claude
```

Open `poc_runs/<time>/masked.json` and check that no real name, device or domain remains.

### 4. Test the email on its own

```bash
python3 poc.py --mail-test
```

### 5. Full run without sending email

```bash
python3 poc.py latest_batch.json --dry-run
```

Read the end of the output:

- `verdict: NORMAL - no alert`, or
- `verdict: ABNORMAL - N verified finding(s)`, followed by each finding title and its `grounding check` line.

The email it would send is saved in `alerts/*.eml` and `poc_runs/<time>/alert.txt`.

### 6. Real run

```bash
python3 poc.py latest_batch.json
```

### 7. Clean up

Delete the raw `latest_batch.json` from the Mac afterwards. It holds real names.

## Command-line options

| Option | Effect |
| --- | --- |
| `--no-claude` | Mask only. Nothing is sent to Claude |
| `--dry-run` | Run everything, but write the email to a file instead of sending it |
| `--mail-test` | Send a test email |
| `--strict-grounding` | Drop findings with details not found in the cited events |
| `--env-file`, `--runs-dir`, `--alerts-dir`, `--map` | Change file locations |

Exit codes: `0` ok, `2` bad input, `3` leak check stopped the run, `4` Claude call failed.

## How Claude's answer is checked

After Claude answers, two Python checks run:

1. **`pipeline.verify()`**: the verdict and severity must be valid values, every cited event id must exist, findings without valid evidence are dropped, and an "abnormal" verdict with nothing left becomes NORMAL.
2. **`grounding.py`**: domains and file names, IP addresses, ports, clock times and repeat counts mentioned in a finding must appear in the events it cites. Ungrounded details are flagged with a caution in the email, or the finding is dropped with `--strict-grounding`.

These checks catch invented details. They do **not** decide whether the activity is really harmful. Claude can still flag harmless activity (false positive) or call harmful activity normal (false negative). Both need more testing to measure.

## What each run leaves behind (`poc_runs/<time>/`)

| File | Content |
| --- | --- |
| `masked.json` | Exactly what Claude received |
| `claude_reply_N.txt` | Claude's raw answer |
| `report.json` | Counts, verdict, verified findings, what verification dropped |
| `alert.txt` | The email text, only if an alert was raised |

## Try it with a harmless simulation (lab VM only)

Example, a network beacon to the Mac (port 4444 is often used by remote-control tools):

On the Mac, start a listener and leave it running:

```bash
python3 -m http.server 4444
```

On the VM, send six requests 10 seconds apart (replace the address with your Mac's address as seen from the VM):

```powershell
1..6 | ForEach-Object { try { Invoke-WebRequest -Uri "http://192.168.64.1:4444/check" -UseBasicParsing | Out-Null } catch {}; Start-Sleep 10 }
```

Check that Sysmon logged it:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3; StartTime=(Get-Date).AddMinutes(-10)} | Where-Object { $_.Message -match '192.168.64.1' } | Select-Object -First 3 TimeCreated
```

Then collect (`-LookbackMinutes 10`), copy the file and run `python3 poc.py <file> --dry-run`. You know what you did, so you can judge Claude's verdict.

Other scenarios tested in the report: idle (normal) activity, suspicious domain lookups (event 22), and a hidden PowerShell script run from the Temp folder followed by account and network discovery commands (event 1). Registry persistence, file drop and encoded PowerShell are left for future development.

## Cost

One check per day is a few thousand tokens. On a Claude Pro plan there is no per-call bill, only the plan's usage limits ($20 per month, or $17 billed yearly). At pay-per-use API prices it is roughly $0.20 per month (estimate, not a measurement). The Pro plan is for one individual.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `SSLCertVerificationError: CERTIFICATE_VERIFY_FAILED` on the email step | The python.org build of Python on macOS has no root certificates. Run its `Install Certificates.command` (in `/Applications/Python 3.x/`), or `pip3 install certifi` and set `SSL_CERT_FILE` to the path `python3 -c "import certifi; print(certifi.where())"` prints |
| Where is Python installed? | `which python3` and `python3 -c "import sys; print(sys.executable)"` |
| Sysmon logs nothing for a test | Check the configuration (`Sysmon64.exe -c`). Events without a rule are not recorded |
| `Get-WinEvent : No events were found` | Sysmon did not log that event in the window. Check the event type with the Group-Object command above |
| Collector output has no events | Use `-LookbackMinutes 30`, or delete `collector_state.json` and run again |
| Leak check stopped the run (exit 3) | A real value survived masking. Do not send anything. Look at the message, add the word to `SENSITIVE_TERMS`, and run again |
| Claude CLI not found | Install Claude Code and run `claude` once to sign in; or set `CLAUDE_CLI` to the full path |
| The alert lists the collector's own job or Sysmon | Known limitation: the tool can flag its own helpers. Treat these as likely false positives |

## Limits

- Manual, so there is no real-time alerting. A run covers the time since the last collection.
- There is no memory between runs: running the same file twice sends the same alert twice.
- Claude's answers can differ between runs. This needs extensive testing on more events.
- Verification checks that cited events and details exist. It does not prove Claude's reasoning is right.
- Detection depends on the Sysmon configuration.
- Lab data only. No real person's activity was used.

## Future work

- Extend testing to other attack events, and measure false positives and false negatives over days of normal activity.
- Add parent-process and service context to the prompt.
- Compare each batch against a normal-activity baseline for the same machine.
- Add a simple rule-based cross-check.
- Use a local AI model so no data leaves the machine.
- Send events automatically from the VM to a central console, replacing the manual copy.
