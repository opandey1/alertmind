# Host-only Ubuntu archive comparison — PID 1 candidate

Status: **proposed, unexecuted owner packet; independent review pending**.
Codex completed a separate [Windows-host smoke test](../../evidence/rbac/pid1-ubuntu-archive-host-smoke-2026-09-28.md)
with the public archive bundle; that is not owner execution or approval.
This is a Windows-host public-artifact check, **not** a clone or original-VM
command. It does not download to, update, connect or change either VM. The
owner reports no AlertMind app is currently running against the isolated
`Ubuntu SOC 201 - Current Isolated Clone`; that does not reconstruct app state
at the earlier Gate 1 instant. Leave its adapters disconnected. It may remain
off throughout this packet.

The verifier in [`siem/rbac/verify_pid1_ubuntu_archive.py`](../../siem/rbac/verify_pid1_ubuntu_archive.py)
checks, in order: the GPG-valid `resolute-updates` InRelease signed by the
reviewed Ubuntu archive key fingerprint; its SHA-256 and length for
`main/binary-amd64/Packages.xz`; that index's exact `systemd` version,
architecture, filename, `.deb` length and SHA-256; and the binary extracted
from the authenticated `.deb` against the owner-reported [clone candidate](../../evidence/rbac/pid1-current-clone-preflight-2026-09-28.md).
It parses public files only, runs `gpgv` and `tar` without a shell, and
prints fixed errors or sanitized hash metadata. It never creates a PID 1
reference or sets any maintenance-admission flag. It cannot independently
attest the Windows host, Gpg4win/Python/tar installation, provenance of the
downloaded key, current clone/original state or future package updates.
Its input read limits are checked before and after a read; subprocess output
limits are checked after each bounded-time tool exits, not streamed as hard
memory caps. Do not run it on an untrusted host or with unreviewed tool paths.

## Host preflight

Run in an ordinary, non-administrator PowerShell session on the **physical
Windows host**. No VM terminal, SSH tunnel, WSL, APT, dpkg or systemd command
is used. Do not run this packet if the host/toolchain is untrusted. These
paths were observed on the owner's host; if a tool is missing or a path
changes, stop for review rather than substituting an arbitrary binary.

```powershell
Set-Location 'C:\Users\ojasp\Desktop\project-alertmind\alertmind-main\alertmind'
$Gpg = (Get-Command gpg.exe -ErrorAction Stop).Source
$Gpgv = (Get-Command gpgv.exe -ErrorAction Stop).Source
$Tar = (Get-Command tar.exe -ErrorAction Stop).Source
$Python = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw 'STOP: pinned Python path absent' }
if ($Gpgv -notlike '*\GnuPG\bin\gpgv.exe' -or
    $Gpg -notlike '*\GnuPG\bin\gpg.exe' -or
    $Tar -ne 'C:\Windows\System32\tar.exe') { throw 'STOP: verifier tool paths changed' }
& $Python --version
& $Gpgv --version | Select-Object -First 1
& $Tar --version | Select-Object -First 1
```

Python must report 3.12 or later; `tar` must report `bsdtar` with zstd support.
Gpg4win's public-key verification is separate from trusting its local binary.
If any check fails, stop. The PowerShell commands below create only a fresh
temporary folder containing **public** key and package artifacts.

## Acquire one exact, disposable bundle

Ubuntu's [archive-integrity documentation](https://documentation.ubuntu.com/security/software-integrity/archive-verification/)
explains the signed Release → package index → `.deb` hash chain. The
[Ubuntu Security FAQ](https://wiki.ubuntu.com/Security/FAQ) publishes the
2018 Archive Automatic Signing Key fingerprint
`F6ECB3762474EDA9D21B7022871920D1991BC93C`.
This fingerprint is compiled into the verifier; a different signer stops.
Obtain the public key over HTTPS from Ubuntu's keyserver and check its
fingerprint **before** invoking the verifier. Do not alter your normal GPG
home/keyring.

```powershell
$Root = Join-Path $env:TEMP 'alertmind-pid1-archive-2026-09-28'
if (Test-Path -LiteralPath $Root) { throw 'STOP: bundle path already exists' }
New-Item -ItemType Directory -Path $Root -ErrorAction Stop | Out-Null
$GpgHome = Join-Path $Root 'gnupg'
New-Item -ItemType Directory -Path $GpgHome -ErrorAction Stop | Out-Null
$KeyUrl = 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xF6ECB3762474EDA9D21B7022871920D1991BC93C'
Invoke-WebRequest -Uri $KeyUrl -OutFile (Join-Path $Root 'archive-key.asc') -ErrorAction Stop
$KeyLines = @(& $Gpg --homedir $GpgHome --batch --show-keys --with-colons (Join-Path $Root 'archive-key.asc') 2>$null)
if ($LASTEXITCODE -ne 0) { throw 'STOP: cannot inspect archive key' }
$Fingerprints = @($KeyLines | Where-Object { $_ -like 'fpr:*' } |
    ForEach-Object { ($_ -split ':')[9] })
if ($Fingerprints.Count -ne 1 -or
    $Fingerprints[0] -ne 'F6ECB3762474EDA9D21B7022871920D1991BC93C') {
    throw 'STOP: archive key fingerprint mismatch'
}
& $Gpg --homedir $GpgHome --batch --yes --dearmor --output (Join-Path $Root 'ubuntu-archive-keyring.gpg') (Join-Path $Root 'archive-key.asc')
if ($LASTEXITCODE -ne 0) { throw 'STOP: keyring conversion failed' }
```

Download only the exact public files below, all on the Windows host. A mirror
rotation between `InRelease` and `Packages.xz` may produce a hash mismatch;
that is a stop requiring a fresh bundle, not a reason to bypass verification.
The listing's [candidate `.deb` checksum](https://packages.ubuntu.com/resolute-updates/amd64/systemd/download)
is supplementary; the verifier obtains the authoritative hash from the
GPG-verified package index.

```powershell
$Base = 'https://archive.ubuntu.com/ubuntu'
$Files = @(
    @('dists/resolute-updates/InRelease', 'InRelease'),
    @('dists/resolute-updates/main/binary-amd64/Packages.xz', 'Packages.xz'),
    @('pool/main/s/systemd/systemd_259.5-0ubuntu3.4_amd64.deb', 'systemd_259.5-0ubuntu3.4_amd64.deb')
)
foreach ($Pair in $Files) {
    $Target = Join-Path $Root $Pair[1]
    if (Test-Path -LiteralPath $Target) { throw 'STOP: artifact already exists' }
    Invoke-WebRequest -Uri "$Base/$($Pair[0])" -OutFile $Target -ErrorAction Stop
}
```

## Verify and stop for review

```powershell
& $Python -B .\siem\rbac\verify_pid1_ubuntu_archive.py `
    --bundle $Root --gpgv $Gpgv --bsdtar $Tar `
    --candidate-sha256 3c4b78ddb68e29e23da0465dd273f1ee82f5b9439ebfcec9798b395c05a2c1e3 `
    --candidate-bytes 141776
if ($LASTEXITCODE -ne 0) { throw 'STOP: archive-chain candidate verification failed' }
```

Return only the tool-version lines, the `PASS`-equivalent sanitized JSON or
the fixed `STOP` code. Do not paste raw public artifacts, GPG diagnostic
text, any credentials, system files or VM output. A successful local run
demonstrates a **candidate comparison through a verified archive signature**;
it does not by itself approve the key's provenance, a reference pin, the
dormant native observer, the original VM or any live maintenance action.
The [next-gate plan](rbac-pid1-clone-provenance-plan.md) still requires
independent review and a separate clone-native compatibility packet.
