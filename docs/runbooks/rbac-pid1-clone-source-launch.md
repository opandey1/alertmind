# PID 1 clone Gate 2B — verified source staging and launch candidate

Status: **offline implementation; staging packet unexecuted; independent review pending**.
Gate 2A [is complete](../../evidence/rbac/pid1-clone-native-probe-2026-09-30.md).
Do not repeat it. This package prepares the actual image observer without
importing a writable checkout as root. **No root observation command is released**
by this packet. Staging results must be accepted first; runtime trust and the
separate bounded observation command remain an explicit release decision.

The renderer bundles eight exact LF source files in dependency order inside
one standalone script. Its private empty-path package loads verified bytes,
not filesystem modules or project `__init__.py` files. Verification mode checks
all hashes and compiles all sources **without executing them**. Observation
mode calls only `observe_pid1_image_inventory()`; imported dependencies contain
other functions but none of their service/process observers are called.
The census's unused deferred namespace import is deliberately not bundled.

This is a disposable-clone diagnostic, not the production startup guard, its
full runtime policy, or a maintenance-admission path. Root-owned staged files
exclude ordinary-user source substitution, not a hostile root/kernel. Isolated
Python flags and byte checks cannot authenticate already loaded interpreter,
stdlib/native code or initial loader inputs. The clone OS/toolchain must be
trusted externally before any privileged observation is released. Existing
archive-chain review and all deferred independent-review obligations remain open.

## Block 1 — render on the Windows host only

Use the identified clean, merged repository on the physical Windows host.
No network, VM connection, credentials or model call is needed. The clone may
remain off. The output file is a new public build artifact, not frozen evidence.
The builder uses exclusive creation and refuses to overwrite an existing file.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    Set-Location 'C:\Users\ojasp\Desktop\project-alertmind\alertmind-main\alertmind'
    if (@(git status --porcelain).Count -ne 0) { throw 'STOP: checkout is not clean' }
    if ($LASTEXITCODE -ne 0) { throw 'STOP: Git status failed' }
    $Expected = '5b15151c91c3f6a2eb0e473489df1d70485cbe7c03cb1d8ffa22b7dc21c98106'
    $Output = Join-Path $env:TEMP 'alertmind-pid1-clone-2b-20260930.py'
    if (Test-Path -LiteralPath $Output) { throw 'STOP: build output already exists' }
    $BuildLines = @(python -B .\siem\rbac\build_pid1_clone_packet.py --output $Output)
    if ($LASTEXITCODE -ne 0) { throw 'STOP: source packet build failed' }
    $Build = ($BuildLines -join "`n") | ConvertFrom-Json -ErrorAction Stop
    $Observed = (Get-FileHash -LiteralPath $Output -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Observed -ne $Expected -or $Build.sha256 -ne $Expected -or
        $Build.bytes -ne 121691 -or $Build.source_count -ne 8 -or
        $Build.observer_executed -ne $false -or $Build.review_required -ne $true) {
        throw 'STOP: generated source packet differs from the reviewed candidate'
    }
    $Encoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Output))
    $Wrapped = (@([regex]::Matches($Encoded, '.{1,76}') | ForEach-Object { $_.Value }) -join "`n")
    Set-Clipboard -Value ($Wrapped + "`nALERTMIND_PUBLIC_SOURCE_END")
    'PASS host packet SHA-256: ' + $Observed
    'PASS host packet: bytes=121691 source_count=8; observer not executed'
    'PASS clipboard: wrapped public Base64 and end marker only'
    'STOP POINT: retain the output; transfer to the isolated clone only after review'
}
```

Send only the PASS/STOP lines, not the Base64. A changed source or template
changes this external checksum and must stop rather than update the expected
value automatically. Existing host output is preserved on failure; do not
overwrite it or reuse an uncertain clipboard value.

## Block 2 — stage on the isolated clone, not the original VM

After Block 1 is accepted, use the console of
**Ubuntu SOC 201 - Current Isolated Clone**, identified in VirtualBox by its VM entry/settings. Confirm
all network adapters remain disconnected, no AlertMind app uses it, no
updates/configuration changes intervened and the original VM is untouched.
Public staging is the only intentional clone change in this block. Do not
enable an adapter, install packages, use SSH/shared folders or run a service command.
Shared Clipboard may carry only these public bytes; alternatively stop and
request an approved offline transfer if Clipboard is unavailable.

Run the entire subshell as `notroot` in one paste. At the Base64 prompt,
paste **only** the wrapped value and end marker prepared in Block 1, then
press Enter once if needed. Lines are at most 76 characters to avoid the
terminal's canonical-input line limit. Do not
paste this Bash block into that prompt. The root destination is new and
separate from every existing guard/service path. No prior directory is reused.
The checksum below is external to the generated script.

```bash
(
set -euo pipefail
umask 077
trap 'printf "%s\n" "STOP: SOURCE_STAGE_FAILED"; exit 1' ERR
[ "$(id -u)" -ne 0 ] || { printf '%s\n' 'STOP: use the unprivileged clone console user'; exit 1; }
read -r -p 'Type CLONE-ONLY after checking clone identity, disconnected adapters, no app use and no intervening updates: ' ready
[ "$ready" = CLONE-ONLY ] || { printf '%s\n' 'STOP: clone conditions not confirmed'; exit 1; }
stage="$HOME/alertmind-pid1-clone-2b-public"
root_stage='/root/alertmind-pid1-clone-2b'
expected='5b15151c91c3f6a2eb0e473489df1d70485cbe7c03cb1d8ffa22b7dc21c98106'
[ ! -e "$stage" ] && [ ! -L "$stage" ] || { printf '%s\n' 'STOP: public stage exists'; exit 1; }
sudo test ! -e "$root_stage"
sudo test ! -L "$root_stage"
install -d -m 700 "$stage"
printf '%s\n' 'Paste wrapped public Base64, ending with ALERTMIND_PUBLIC_SOURCE_END:'
encoded=''
ended=no
for ((count=0; count<4096; count++)); do
    IFS= read -r -s line
    if [ "$line" = ALERTMIND_PUBLIC_SOURCE_END ]; then ended=yes; break; fi
    [[ ${#line} -le 76 && "$line" =~ ^[A-Za-z0-9+/=]+$ ]] || { printf '%s\n' 'STOP: invalid transfer line'; exit 1; }
    encoded+="$line"
    [ ${#encoded} -le 262144 ] || { printf '%s\n' 'STOP: transfer too large'; exit 1; }
done
[ "$ended" = yes ] || { printf '%s\n' 'STOP: transfer end marker absent'; exit 1; }
unset line
[[ ${#encoded} -le 262144 && "$encoded" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || { printf '%s\n' 'STOP: invalid public Base64 input'; exit 1; }
set -o noclobber
printf '%s' "$encoded" | base64 --decode > "$stage/pid1_clone_entry.py"
unset encoded
[ "$(stat -c %s "$stage/pid1_clone_entry.py")" = 121691 ]
printf '%s  %s\n' "$expected" "$stage/pid1_clone_entry.py" | sha256sum -c -
timeout --signal=TERM --kill-after=2s 20s /usr/bin/python3.14 -I -S -B \
    "$stage/pid1_clone_entry.py" --verify-only
sudo install -d -o root -g root -m 700 "$root_stage"
sudo install -o root -g root -m 400 "$stage/pid1_clone_entry.py" "$root_stage/pid1_clone_entry.py"
printf '%s  %s\n' "$expected" "$root_stage/pid1_clone_entry.py" | sudo sha256sum -c -
[ "$(sudo stat -c '%F:%u:%g:%a' "$root_stage")" = 'directory:0:0:700' ]
[ "$(sudo stat -c '%F:%u:%g:%a:%h:%s' "$root_stage/pid1_clone_entry.py")" = 'regular file:0:0:400:1:121691' ]
printf '%s\n' 'PASS root-private staged source: exact checksum, root:root, directory 0700, file 0400'
printf '%s\n' 'PASS clone source stage: source_count=8; no bundled observer executed'
printf '%s\n' 'STOP POINT: return staging output; do not run observation mode'
)
```

Any nonzero command, timeout, unexpected result or STOP is a stop. Preserve
the partial stage; do not retry by changing permissions, paths, checksums or
Python. The unprivileged verification process executes the verified entry's
standard-library bootstrap but **not** any bundled project source. `sudo`
above performs file metadata/copy/hash operations, not Python execution.
Do not treat staging as clone-native observer acceptance.

## Implemented launch policy — held pending staging/runtime acceptance

The standalone script implements an explicit `--observe` mode, never an
automatic continuation of `--verify-only`. The later reviewed launch must:

- Use the fixed root-private entry above, with external checksum and ownership
  rechecked before execution, on the attested isolated clone only.
- Use `/usr/bin/python3.14` version 3.14.4 and its earlier candidate digest
  `52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41`,
  not Wazuh's packaged Python or an auto-learned update. The current entry
  checks the backing executable, not loaded memory or a full native closure.
- Start in `/`, with a cleared environment containing only `HOME=/nonexistent`,
  `LC_ALL=C`, `PATH=/usr/bin:/bin`; isolated/no-site/no-bytecode flags and
  cache prefix `/dev/null/alertmind-pid1-clone`; core limits soft=hard=0.
- Place the process under an external 40-second timeout with a 2-second kill
  grace, independent of the observer's 30-second BOOTTIME window. No service
  jobs or subprocesses are submitted by the observer.

Only after that release, a successful result will contain the exact typed
inventory: boot ID/start ticks, digest, local dpkg version, elapsed time,
two-pass flags and explicit false trust/authority claims. It also requires
equality with the retained candidate digest/version and prints a final STOP
POINT. This comparison is **not** an approved reference. No source content,
raw process record, environment, credential or alert is printed. An observer
failure emits a fixed sanitized code and nonzero exit, never a success footer.

The production guard, maintenance executor and original VM remain untouched.
Independent review must still assess both the native result and archive chain
before any versioned reference or later maintenance gate is admitted.
