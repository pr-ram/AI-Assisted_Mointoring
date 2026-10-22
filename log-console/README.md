# Log pipeline: VM -> Mac console -> mask -> Claude

```
VM (Sysmon events, JSON)
   |  sender.py  (HTTPS, token, batches)
   v
Mac console: receiver.py  ->  events_received.jsonl + console.db
   |
   v
mask_events.py  ->  masked_events.jsonl  (+ mask_map.json, stays on the Mac)
   |
   v
Claude API (online model): analyze + validate the masked events
   |
   v
Mac: Python checks + ground truth, restore real names (--unmask-file), send alert
```

There is no local LLM in this design. The only model is Claude, reached over the
internet, and it only ever sees masked data. The VM never talks to the internet or
to Claude.

Files: `receiver.py` (Mac), `sender.py` (VM), `mask_events.py` (Mac).
Python 3 standard library only. No packages to install for these three.

---

## A. Console (Mac): receive logs

1. Create a token and a self-signed certificate (valid 30 days). Use the address the
   VM uses to reach the Mac. With UTM "Shared Network" this is the VM's Default
   Gateway, usually `192.168.64.1` (it only exists while the VM is running).

       cd ~/log-console
       export CONSOLE_TOKEN="$(openssl rand -hex 24)"
       echo $CONSOLE_TOKEN          # copy it; the VM needs the same value
       openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 30 \
         -subj "/CN=console" -addext "subjectAltName=IP:192.168.64.1"

2. Start the receiver AFTER the VM is running, bound to that address only:

       python3 receiver.py --bind 192.168.64.1 --port 8443 --cert cert.pem --key key.pem

   Allow incoming connections if macOS asks. Output files (in the folder you started
   it from): `events_received.jsonl` (one event per line) and `console.db` (SQLite).

   The token lives only in that Terminal window. A new window needs `export` again.

Check what arrived:

       wc -l events_received.jsonl
       python3 -c "import sqlite3; print(sqlite3.connect('console.db').execute('select host, count(*) from events group by host').fetchall())"

## B. Sender (Windows VM): send logs

Copy `sender.py` and `cert.pem` into the VM. One way: on the Mac put only those two
files in `~/vm_files` (never `key.pem`), run
`cd ~/vm_files && python3 -m http.server 8000 --bind 192.168.64.1`, then in the VM
PowerShell: `curl.exe -O http://192.168.64.1:8000/sender.py` (and `cert.pem`).
Stop the file server afterwards (Ctrl+C).

In PowerShell (not Command Prompt):

       Test-NetConnection 192.168.64.1 -Port 8443          # TcpTestSucceeded : True
       $env:CONSOLE_TOKEN = "PASTE_THE_TOKEN_HERE"          # needed in every new window
       python sender.py --url https://192.168.64.1:8443 --file events.jsonl --host VM-WIN11 --cafile cert.pem

Add `--follow` to keep watching the file and send new lines every 10 seconds.

Input files: JSON Lines (one object per line), a JSON array, or one pretty-printed
object. UTF-8 BOM, CRLF and UTF-16 (what Windows PowerShell writes) are handled. The
file is checked before sending; a bad line is reported with its line number.

Behaviour: 500-event batches, gzip, bearer token, SHA-256 per batch, per-host sequence
numbers. Progress is remembered per file in `sender_state.json`. Network failures keep
the batch in `spool/` and retry in order. A batch the console rejects as malformed
(HTTP 400) is moved to `spool/rejected/` and never blocks later ones.

To resend a file from the start: delete `sender_state.json` (and the `spool` folder).
The receiver then stores those events again, so you will see duplicates.

## C. Mask the data (Mac) before anything goes to Claude

       python3 mask_events.py --in events_received.jsonl --out masked_events.jsonl --map mask_map.json

What it does:
- Replaces user names, computer names, domains, e-mail addresses, private IPs and
  process GUIDs with stable tokens (`USER_1`, `DEVICE_1`, `INTERNAL_IP_1`, `GUID_1` ...).
  The same real value always gets the same token, across runs.
- Applies this everywhere inside text fields, including inside Base64 blobs such as
  PowerShell `-EncodedCommand` (decoded, masked, re-encoded).
- Removes `user:password@` and `?query` from URLs; by default keeps only the file
  extension of the path (`--url-paths keep|ext|drop`).
- Replaces secrets in command lines (`password=`, `--token`, `Bearer ...`, `curl -u user:pass`)
  with `<REDACTED>`.
- Keeps system accounts (`NT AUTHORITY\SYSTEM` etc.), hashes, ports and public IPs.
- Drops empty fields, adds `event_id` (for citations) and `time` (UTC), and removes
  duplicate events.
- Runs a leak check before writing. If a real value is still present, it writes nothing
  and exits with code 3.

Useful options:
- `--sensitive "Smith" "Maple Street"`: extra words to hide everywhere.
- `--public-ips mask`: also hide public IP addresses.
- `--filenames ext`: hide the base name of `TargetFilename`, keep folder and extension.

`mask_map.json` can reverse the masking. It is created owner-only. Never send it,
never e-mail it, never commit it. Restore real names in Claude's answer (for the alert):

       python3 mask_events.py --unmask-file alert.txt --map mask_map.json

Placeholders such as `<PATH>`, `<QUERY>`, `<REDACTED>`, `<FILE>` cannot be restored.

What masking does NOT protect (say this in the report):
- Things that are not in the mapping and not matched by a pattern: a family member's
  first name in a file name, a street name, a school. Use `--sensitive` for known words.
- Public destinations: IPs and domains reveal which sites were used (`--public-ips mask`
  hides IPs, not domains).
- Behavior itself: timing and the sequence of actions can identify a person.
- Secrets in forms the patterns do not recognize. Review a sample of the output.
- Masking is a risk reduction, not anonymization. Use synthetic or lab data only.

Data note: for some network events (Sysmon ID 3) the `UtcTime` field in this VM is about
3 hours off from the event-log `Timestamp`. The masker uses the event-log `Timestamp`,
which matches record order, and prints a warning when they disagree.

## D. Claude API (online model) setup on the Mac (only if you choose CLAUDE_BACKEND=api)

1. Create an API key in the Anthropic Console and set a monthly spend limit there.
2. `pip3 install anthropic`
3. Put the key in the Terminal environment only, never in code or git:

       export ANTHROPIC_API_KEY="your-key"

4. Pick a current model name from the Anthropic docs (names change) and test:

       python3 -c "import anthropic; c=anthropic.Anthropic(); m=c.messages.create(model='MODEL_NAME_HERE', max_tokens=50, messages=[{'role':'user','content':'Say OK'}]); print(m.content[0].text)"

5. Send Claude only the contents of `masked_events.jsonl`, never `events_received.jsonl`
   and never `mask_map.json`.

Cost check: `mask_events.py` prints a rough token estimate of its output. The API
response also reports exact token usage; log it. Prices:
https://platform.claude.com/docs/en/about-claude/pricing

## E. Run it automatically (daily collection) - line-by-line setup

```
VM  Task Scheduler (hourly tick) -> collect_events.ps1 (collects ONCE a day, after 19:00)
                                   -> latest_batch.json -> sender.py --mode snapshot
                                                                   |  HTTPS, token, SHA-256
Mac launchd: receiver.py (always on) -> events_received.jsonl
Mac launchd: pipeline.py (every 2 min) -> mask -> leak check -> Claude (normal/abnormal)
                                         -> Python verifies evidence ids -> unmask locally -> e-mail
```
Daily schedule (defaults): the VM collects once, at the first hourly tick after 19:00, and sends at once; the Mac analyses at 20:00 (`DAILY_RUN_TIME`) and e-mails. So an event can wait up to about a day before you are told. That is the trade-off of daily collection; for demos use `collect_events.ps1 -Force` and `pipeline.py --once --analyze-now`.

### E1. Mac - one time (uses your Claude Pro plan, no API key)
A Claude Pro plan does not include API credits, so the pipeline calls Claude through the **Claude Code CLI** signed in with your Pro account. It runs `claude -p` with all tools disabled, so Claude only reads the masked text and answers.
1. Start the VM first, because 192.168.64.1 only exists while it runs.
2. Install Claude Code on the Mac: `curl -fsSL https://claude.ai/install.sh | bash` (or `brew install --cask claude-code`). Open a new Terminal and check `claude --version`.
3. Sign in with your Pro account: run `claude`, choose **Claude account with subscription**, finish the browser login, then type `/exit`. Check with `claude auth status --text` (it must say claude.ai, not api_key).
4. Make sure no API key is set in your shell: `echo $ANTHROPIC_API_KEY` must print nothing. (The pipeline also ignores it, so you are never billed API credits by accident.)
5. Optional but recommended for a background job: run `claude setup-token`, copy the token it prints and put it in `config.env` as `CLAUDE_CODE_OAUTH_TOKEN=...` (step 7).
6. `cd ~/log-console`, then `cp config.env.example config.env` and `chmod 600 config.env`.
7. Edit `config.env`: keep `CLAUDE_BACKEND=cli` and `CLAUDE_MODEL=haiku`; set `CONSOLE_TOKEN` (generate: `python3 -c "import secrets;print(secrets.token_urlsafe(32))"`), `SENSITIVE_TERMS` (names, school, street), and the `SMTP_*` / `MAIL_*` lines (Gmail App password, not your normal password). Leave `ANTHROPIC_API_KEY` out.
8. Make sure `cert.pem` and `key.pem` (section A) are in this folder.
9. Dry run, nothing is e-mailed: `python3 pipeline.py --once --dry-run`. Expect "no new events" or "verdict: NORMAL". The first real call proves the Pro login works.
10. Install the services: `./install_mac_services.sh`
11. Check: `tail -f receiver.log pipeline.log` and `curl -k https://192.168.64.1:8443/health` (expect `ok`).

Plan limits: Pro usage is shared with your normal Claude chats and resets in rolling windows. The pipeline only calls Claude when there are NEW events, so a quiet laptop costs nothing; if a call fails because the limit is reached, the pipeline keeps the events and retries next cycle. Note it in your report as a limit of this design.

### E2. VM - one time (Administrator PowerShell)
1. Create `C:\SecurityTools` and copy into it: `sender.py`, `cert.pem` (the Mac's cert), and from `vm/`: `collect_events.ps1`, `run_cycle.ps1`, `install_task.ps1`.
2. Create `C:\SecurityTools\sender.env` (copy `vm/sender.env.example`): one line `CONSOLE_TOKEN=` with the SAME value as the Mac.
3. Check Python: `python --version` (python.org install, not the Microsoft Store stub).
4. Test the collector by hand (`-Force` = collect now, ignoring the once-a-day rule): `powershell -ExecutionPolicy Bypass -File C:\SecurityTools\collect_events.ps1 -Force` then `Get-Content C:\SecurityTools\latest_batch.json -TotalCount 1`.
5. Test the sender by hand: `python C:\SecurityTools\sender.py --url https://192.168.64.1:8443 --file C:\SecurityTools\latest_batch.json --host VM-WIN11 --cafile C:\SecurityTools\cert.pem --mode snapshot` (expect "sent batch N" or "nothing new to send").
6. Install the schedule: `powershell -ExecutionPolicy Bypass -File C:\SecurityTools\install_task.ps1 -ConsoleUrl https://192.168.64.1:8443`
7. Run the task once now: `Start-ScheduledTask -TaskName LabEventSender`, wait 20 s (it will say `skipped: already collected today` after step 4; that is correct), then `Get-Content C:\SecurityTools\cycle.log -Tail 5`.

### Noise filter in collect_events.ps1 (what is dropped, and why it is safe)
The collector drops two kinds of events and prints the counts (`filtered: self=N, update=N`) in `cycle.log`:
- **self**: the scheduled PowerShell run, `sender.py`, their `conhost.exe`, the files they write (`latest_batch.json`, `cycle.log`, `spool\*.ndjson`, PowerShell profile cache) and the sender's connection to the console.
- **update**: Windows Update (`TiWorker`, `TrustedInstaller`, `usoclient`, `MoUsoCoreWorker` ...), Edge/Chrome/Office updaters, writes into `SoftwareDistribution`/`WinSxS`/`servicing`, and DNS to Microsoft update domains.

Rules are narrow so malware cannot hide behind them: programs are matched by full install path (a `TiWorker.exe` in Temp is still reported); the self rules match the exact command line this project creates; only named files in `C:\SecurityTools` are ignored; updater writes of `.exe/.dll/.ps1...` outside the update folders are kept; updater registry writes are kept when they touch Run keys, Winlogon, IFEO or service ImagePath; Defender's `MpCmdRun.exe` is not filtered (it can download files).
Add other trusted updaters (exact full paths, one per line) to `C:\SecurityTools\noise_extra.txt`. Turn the filter off for a test with `collect_events.ps1 -NoFilter`.
Limit to state in the report: anything an attacker can do as a filtered program with the exact allowed path is not reported, so filtering trades a little coverage for far fewer false alerts.

### E3. Prove the whole chain (lab data only)
1. On the VM run one of the safe test scenarios, e.g. `nslookup evil-phishing-test-domain.com` or add the test HKCU Run key (and delete it afterwards).
2. On the VM run `powershell -ExecutionPolicy Bypass -File C:\SecurityTools\collect_events.ps1 -Force` and then `Start-ScheduledTask -TaskName LabEventSender`. On the Mac wait up to 2 minutes, then run `python3 pipeline.py --once --analyze-now` (daily mode otherwise waits for 20:00).
3. Mac: `tail pipeline.log` shows `masked N events`, `verdict: ABNORMAL` and `ALERT e-mailed`. Open `masked/` to see exactly what Claude received (no real names).
4. After each test, record in your ground-truth table: scenario, expected verdict, actual verdict, time to alert.

### E4. Daily use / after a restart
- Mac: nothing to do; launchd restarts both jobs. VM off -> receiver retries every 30 s until it is on.
- VM: nothing to do; the task ticks hourly and collects once a day. If the Mac is off, batches wait in `C:\SecurityTools\spool` and are resent in order.
- Stop everything: Mac `./install_mac_services.sh uninstall`; VM `Unregister-ScheduledTask -TaskName LabEventSender -Confirm:$false`.

### Once-a-day collection on the VM
- `collect_events.ps1` collects only if it has not collected today and the local time is at or after `-AfterHour` (default 19). Its window is "since the last collection" (first run 24 h, at most 72 h), so a day with the VM off is not lost.
- The state is in `C:\SecurityTools\collector_state.json`. Delete it to make the next run collect the last 24 h again.
- Identical repeats are not merged on the VM; the Mac merges them once (`count`, `last_time`).
- The tool folder is made writable by Administrators/SYSTEM only (`install_task.ps1`), because the self-noise rules trust that folder.

### How the automatic rules behave
- **Claude runs once a day (default, `CLAUDE_RUN_MODE=daily`).** Every 2 minutes the pipeline still masks the new events and merges them into `pending_masked.json` (duplicates removed, repeats merged across the whole day). At `DAILY_RUN_TIME` (default 20:00 Mac time) it sends everything waiting to Claude in one run, verifies the answer and e-mails any finding. If the Mac was off at that time it runs at the first check afterwards. If Claude fails it keeps the events and retries on the next cycles, at most `MAX_ATTEMPTS_PER_DAY` (3) times. `python3 pipeline.py --once --analyze-now` forces a run (for demos and tests). Set `CLAUDE_RUN_MODE=cycle` for near real time. Trade-off for the report: daily is cheap but an incident can wait up to a day before you are told.
- Only NEW events are sent (snapshot mode fingerprints every event; overlap between runs is harmless).
- If Claude is unreachable, the pipeline does not advance and retries the same events next cycle.
- If the leak check fails, the batch is saved to `quarantine/` and nothing is sent to Claude.
- Findings Claude cites without real event ids are dropped (logged as `verify:`).
- E-mail only for findings at or above `MIN_SEVERITY`; the same behaviour is not e-mailed twice; at most `MAX_ALERTS_PER_HOUR`. If SMTP fails an `.eml` is saved in `alerts/`.
- Monitor and alert only: no step blocks, kills or changes anything on the VM.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `Set CONSOLE_TOKEN in the environment` | Token not set in this window. `$env:CONSOLE_TOKEN = "..."` (VM) or `export CONSOLE_TOKEN=...` (Mac). |
| `HTTP 401 unauthorized` | VM and Mac tokens differ. Check for spaces or a missing character. |
| `HTTP 400 ... bad json line` | Old `sender.py`, or a file that is not JSON. Use the current sender; it names the bad line. |
| `Test-NetConnection is not recognized` | You are in Command Prompt. Type `powershell` first. |
| `Address already in use` | An old server holds the port. `lsof -i :8000` then `kill <PID>`, or use another port. |
| `nodename nor servname provided` | A placeholder like `MAC_IP` was typed literally. Use the real address. |
| `Can't assign requested address` | The VM is not running yet, so `192.168.64.1` does not exist. Start the VM first. |
| `Select-String: command not found` (Mac) | That is a PowerShell command. On the Mac use `grep`. |
| Certificate error | The IP in `cert.pem` must equal the IP in `--url`. Recreate the certificate if the address changed. |

## Known limits (state them in the report)

- One shared token for all senders; self-signed certificate (30 days).
- Console data files grow forever and are not rotated.
- Masking is rule-based and cannot catch everything (see section C).
- Tested locally: TLS send, per-file progress, JSON array / pretty / UTF-16 / BOM input,
  bad-line detection, rejected-batch quarantine, duplicate and tampered batches, console
  down and recovery, masking (real file and synthetic secrets, e-mails, URLs, encoded
  commands), leak check, mapping stability across runs, unmask round trip.
- Verified by you end to end: VM -> Mac transfer in UTM Shared Network.
- Not tested: sending the masked data to Claude, and more than one sender.
