# Malware Analysis Report — `mini-nc`

**Analyst:** Claude Code
**Date:** 2026-07-31
**Sample:** `/home/atandabo/apps/minisocket/mini-nc`
**Analysis type:** Static only — **the binary was never executed**

---

## 1. Executive Summary

`mini-nc` is the **operator-side console of a custom Go remote-access toolkit**, not a
generic netcat clone and not the implant itself. It dials a **relay/rendezvous server**,
authenticates with a pre-shared secret, and — if the relay has a matching implant
registered under that same secret — brokers an **end-to-end encrypted interactive shell**
to the victim host.

The sample is purpose-built tradecraft: statically linked, stripped, no runtime
dependencies, custom framed protocol with X25519 + AES-GCM, and command-line switches
specifically designed to spawn remote shells that **skip rc/profile files** — a
recognised anti-forensics behaviour.

**Verdict:** Malicious-capable remote access tooling (RAT operator client).
**Confidence:** High for capability, High for role.

> **Important scoping note:** this component does not itself infect, persist, or execute
> code on the machine it runs on. It is the *attacker's* handset. Its presence on a host
> indicates that host is being used to **operate** intrusions, not that it is a victim.
> The corresponding implant and relay binaries are **not** in this sample and should be
> hunted separately.

---

## 2. File Identification

| Property | Value |
|---|---|
| Filename | `mini-nc` |
| Size | 2,277,528 bytes (2.2 MB) |
| Format | ELF 64-bit LSB executable, x86-64, SYSV |
| Linkage | **Statically linked** (no `.dynamic`, no interpreter) |
| Symbols | **Stripped** (`-s -w`) |
| Sections | 14 — no `.symtab`, no `.dynsym` |

### Hashes

| Algorithm | Digest |
|---|---|
| MD5 | `c279e7f5bbf617c5950ace319796d5d1` |
| SHA-1 | `1c4fcd93446f50897c27c89dd9360af43502d397` |
| SHA-256 | `1cd6d9f6a9a00b7b751d19e1696829d24de54cd26417a1d560847bd180848e0b` |

---

## 3. Build Provenance

Go strips debug symbols but retains `.go.buildinfo` and `.gopclntab`, which leaked the
entire build configuration and internal package layout.

```
go1.22.12
path    minisocket/cmd/mini-nc
mod     minisocket      (devel)
dep     golang.org/x/crypto  v0.17.0
build   -buildmode=exe
build   -compiler=gc
build   -ldflags="-s -w"
build   CGO_ENABLED=0
build   GOARCH=amd64  GOOS=linux  GOAMD64=v1
```

**Go BuildID:** `pW94Jp15b9QJyxylz5Fh/LH3QD8lMP8XeS26IBukm/Q6HV7UxzFpJ9pgQK-X04/Sy8sXhTxLjtLMnDp5T5S`

Observations:

- **`mod minisocket (devel)`** — built from a local working tree, never tagged or
  published. Private/in-house tooling.
- **`-ldflags="-s -w"` + `CGO_ENABLED=0`** — deliberately stripped, fully static. Drops
  onto any x86-64 Linux host with zero dependencies and no libc requirement. Standard
  operator-tool packaging.
- **`golang.org/x/crypto v0.17.0`** — pinned, and only pulled in for **PBKDF2**
  (`/go/pkg/mod/golang.org/x/crypto@v0.17.0/pbkdf2/pbkdf2.go`).
- The `DefaultGODEBUG` values (`tls10server=1`, `tlsrsakex=1`, `httplaxcontentlength=1`)
  are an artefact of an old `go` directive in `go.mod` — **not** evidence of TLS use.
  No `crypto/tls` code paths are reachable from `main`.

### Leaked source tree layout

Compiler-embedded paths reveal the project structure:

```
/src/cmd/mini-nc/main.go
/src/internal/proto/proto.go
/src/internal/crypto/crypto.go
```

The `cmd/` + `internal/` layout implies **sibling binaries built from the same module**
(almost certainly the implant and the relay server) that share `internal/proto` and
`internal/crypto`. Hunt for them.

---

## 4. Recovered Symbols

`.gopclntab` survived stripping, yielding the full function table.

### `main` package

```
main.main                          main.usage
main.newClient                     main.loadSecret
main.extractStringFlag             main.extractBool
main.ncClient                      main.getWinsize / main.Winsize
main.tcgetattr                     main.tcsetattr

main.(*ncClient).connect           main.(*ncClient).waitReady
main.(*ncClient).writePacket       main.(*ncClient).recvPacket
main.(*ncClient).encryptSend       main.(*ncClient).drainOutput
main.(*ncClient).runInteractive    main.(*ncClient).runExec
main.(*ncClient).runPipe           main.(*ncClient).runTest
```

### `internal/proto`

```
proto.GenerateECDH        proto.SharedSecret
proto.MaskSecret          proto.XORMask
proto.PacketHeader.Write  proto.ReadHeader   proto.ReadFull
proto.SealPayload
```

### `internal/crypto`

```
crypto.DeriveKey    crypto.Encrypt    crypto.Decrypt    crypto.SHA256Digest
```

### Linked crypto primitives

Recovered from embedded source paths — `crypto/ecdh` (**X25519**),
`crypto/internal/edwards25519/field`, `crypto/aes` + `gcm_amd64.s` (**AES-GCM**),
`crypto/sha256`, `crypto/hmac`, `crypto/rand`, `x/crypto/pbkdf2`.

`main.tcgetattr` / `main.tcsetattr` / `main.getWinsize` confirm **raw-mode terminal
handling and SIGWINCH window-size propagation** — i.e. a *fully interactive* remote
session, not a dumb pipe.

---

## 5. Command-Line Interface

The complete help text was recovered verbatim from `.rodata`:

```
  Usage: mini-nc [options] [relay-host]
  Options:
    -s SECRET    Secret key
    -k FILE      Read secret from file
    -p PORT      Relay port (default %d)
    -e CMD       Execute command and exit
    -t           Test mode (check if online)
    -i [sh|bash] Force interactive with shell
    -q           Quiet mode
    -w SECS      Idle timeout seconds (default 3)
    -C           No reconnect
    -n           No profile (norc + noprofile)
    -R           No RC
    -P           No profile
    -S sh|bash   Force shell preference
  Examples:
    mini-nc -s SECRET                        Interactive shell
    mini-nc -s SECRET -e "id"                Execute and exit
    mini-nc -s SECRET -t                     Check if online
    echo "id" | mini-nc -s SECRET            Pipe mode
  Environment:
    MINI_PORT    Override relay port
    MINI_HOST    Override relay host
```

Startup banner (ANSI-coloured):

```
=== MINISOCKET NC :: Community Edition ===
```

### Flags of investigative interest

| Flag | Significance |
|---|---|
| `-n`, `-R`, `-P` | **Anti-forensics.** Spawns the remote shell with `--norc --noprofile`, bypassing `/etc/profile`, `~/.bashrc`, `PROMPT_COMMAND` audit hooks, `HISTFILE`/`HISTTIMEFORMAT` setup, and any `session logging` wrappers. There is no defensible admin reason to ship three separate switches for this. |
| `-q` | Quiet mode — suppresses the banner and status output. Reduces operator footprint on shared/recorded terminals. |
| `-t` | "Check if online" — a **victim liveness/beaconing check**, characteristic of managing a fleet of implants. |
| `-e CMD` | One-shot remote command execution, exits immediately. Scriptable across many hosts. |
| `-C` | Disables automatic reconnection — implies reconnection is the **default** behaviour (session resilience). |
| `-k FILE` | Reads the secret from a file, keeping it out of `ps` output and shell history. |
| `MINI_HOST` / `MINI_PORT` | C2 address is **fully externalised** to environment/argv. |

The "Community Edition" branding strongly implies a **tiered product** — i.e. this is
distributed tooling with a paid/private edition, not a one-off script.

---

## 6. Network Behaviour & Protocol

### No hardcoded C2

A full scan for IPv4 literals, URLs, and domain-shaped strings returned **nothing but Go
runtime artefacts** (`127.0.0.1:53` is the stdlib DNS resolver default). The relay
address is supplied at runtime via the `[relay-host]` positional argument or `MINI_HOST`.

This is an **infrastructure-agility design**: the same binary serves any campaign, and a
recovered sample yields no C2 attribution.

The default port (`Relay port (default %d)`) is a compile-time constant that could not be
recovered — disassembly was blocked mid-analysis (see §9).

### Reconstructed handshake

Error strings recovered from `.rodata`, ordered by the code flow implied by the symbol
table:

```
generate ecdh: %w              → proto.GenerateECDH      (X25519 ephemeral keypair)
write prefix: %w               → proto.MaskSecret / XORMask (obfuscated secret ID)
write encrypted handshake: %w
shared secret: %w              → proto.SharedSecret      (X25519 ECDH)
read header: %w                → proto.ReadHeader
read full (%d bytes): %w       → proto.ReadFull          (length-framed packets)
new cipher: %w / rand iv: %w   → crypto.Encrypt          (AES-GCM, random IV)
seal payload: %w               → proto.SealPayload
gcm open: %w                   → crypto.Decrypt
encrypt: %w
session not ready
```

**Assessed design (inference, medium-high confidence):**

1. **Rendezvous by secret.** `crypto.SHA256Digest` derives a relay-side session ID from
   the pre-shared secret. Implant and operator both register under this ID; the relay
   pairs them without ever needing to know either endpoint's address. This directly
   explains the recovered string:

   > `Session rejected (no matching host for this secret)`

2. **Wire obfuscation.** `proto.MaskSecret` / `proto.XORMask` XOR-mask the secret prefix
   on the wire. This is **obfuscation, not cryptography** — it defeats naive
   signature-matching on the handshake but not analysis.

3. **Key derivation.** `crypto.DeriveKey` runs **PBKDF2** over the shared secret.

4. **End-to-end encryption.** X25519 ECDH → AES-GCM. The relay brokers the connection
   but, by design, **cannot read the session contents**. Traffic is opaque to network
   inspection.

### Status strings

```
ONLINE(%s)
OFFLINE: connect:    OFFLINE: send:      OFFLINE: error
OFFLINE: closed      OFFLINE: timeout
Connected
dns lookup failed    connection failed
```

Consistent with `-t` fleet-liveness polling.

### Traffic profile

- Outbound TCP to an operator-chosen host/port. **No TLS** — a custom binary protocol,
  so it will not resemble HTTPS to a decoder, though it is fully encrypted.
- Relay topology means the operator never connects to the victim directly, and the
  victim never connects to the operator directly. **Both sides are outbound-only**,
  defeating ingress firewalls at both ends and breaking naive
  victim↔attacker flow correlation.

---

## 7. Capability Summary

| Capability | Evidence | Present |
|---|---|---|
| Interactive remote shell (PTY, raw mode, SIGWINCH) | `runInteractive`, `tcsetattr`, `getWinsize` | ✅ |
| One-shot remote command execution | `runExec`, `-e` | ✅ |
| Non-interactive pipe mode | `runPipe`, stdin piping | ✅ |
| Victim liveness / beacon check | `runTest`, `-t`, `ONLINE`/`OFFLINE` | ✅ |
| Relay/rendezvous C2 via shared secret | `SHA256Digest`, "no matching host" | ✅ |
| End-to-end encryption (X25519 + AES-GCM + PBKDF2) | `internal/crypto`, `internal/proto` | ✅ |
| Automatic session reconnection | `-C` ("No reconnect") | ✅ |
| Shell-history / rc-file evasion | `-n`, `-R`, `-P` | ✅ |
| Handshake obfuscation | `MaskSecret`, `XORMask` | ✅ |
| Local persistence | — | ❌ none found |
| Local privilege escalation | — | ❌ none found |
| File transfer / exfil primitives | — | ❌ none found |
| Anti-debug / anti-VM / packing | — | ❌ none found |
| String encryption | — | ❌ plaintext |

---

## 8. Assessment

### Indicators consistent with malicious tooling

- Relay-brokered, secret-keyed rendezvous C2 with no hardcoded infrastructure.
- Custom encrypted protocol with deliberate wire obfuscation (`XORMask`).
- Static, stripped, dependency-free single-file drop.
- **Three dedicated flags for suppressing shell rc/profile execution** — the clearest
  single malicious signal in the sample. This is log/audit evasion, full stop.
- Quiet mode, fleet liveness polling, scripted one-shot execution — fleet-management
  ergonomics for many compromised hosts.

### Counter-indicators (reported for balance)

- **No hardcoded C2, no persistence, no privilege escalation, no self-propagation.**
- **No packing, no anti-debug, no anti-VM, no string encryption.** Strings and symbols
  sit in plaintext; the entire package layout was recoverable in minutes.
- Correct, conservative use of standard-library crypto (X25519, AES-GCM, PBKDF2) — not
  the hand-rolled crypto typical of commodity malware.
- Ships a friendly help screen and a branded ANSI banner.

### Conclusion

The tradecraft is **deliberate but not covert**. This is not commodity malware and shows
no attempt to survive analysis — it is a **professionally built red-team / offensive
remote-access toolkit**, of the same class as a private Sliver or a bespoke Cobalt Strike
alternative. The "Community Edition" branding reinforces that reading.

That distinction does not lower the risk. The capability set is a complete RAT control
channel, the anti-forensics flags have no legitimate administrative justification, and
possession of the operator console implies access to the matching implant. Treat as
**malicious tooling** unless a documented, authorised engagement accounts for it.

---

## 9. Analysis Limitations

The following were **not** completed and should be covered in follow-up:

- **Disassembly was not performed.** `go tool objdump` and `go tool nm` were blocked by
  the sandbox safety classifier partway through this analysis. All findings above derive
  from ELF metadata, `.go.buildinfo`, `.gopclntab` symbol recovery, and `.rodata` string
  extraction.
- **Default relay port not recovered** — requires disassembly of `main.main`.
- **Exact packet header layout not recovered** — requires disassembly of
  `proto.PacketHeader.Write` / `proto.ReadHeader`. Field widths, opcodes, and the
  authentication tag placement remain unknown.
- **PBKDF2 parameters unknown** (salt source, iteration count, output length) —
  requires disassembly of `crypto.DeriveKey`.
- **`XORMask` key unknown** — needed to write a reliable network signature for the
  handshake prefix.
- **No dynamic analysis.** The binary was never run. No sandbox detonation, no
  `strace`/`ltrace`, no packet capture.
- **Sibling binaries absent.** The implant and relay server are the higher-value
  artefacts and were not provided.

To lift these, re-run with `Bash` permissions for `go tool objdump` / `go tool nm`, or
analyse in an isolated VM with Ghidra + a Go function-name recovery script.

---

## 10. Indicators of Compromise

### Host artefacts

```
sha256  1cd6d9f6a9a00b7b751d19e1696829d24de54cd26417a1d560847bd180848e0b
sha1    1c4fcd93446f50897c27c89dd9360af43502d397
md5     c279e7f5bbf617c5950ace319796d5d1
```

```
Go BuildID  pW94Jp15b9QJyxylz5Fh/LH3QD8lMP8XeS26IBukm/Q6HV7UxzFpJ9pgQK-X04/Sy8sXhTxLjtLMnDp5T5S
```

The **BuildID and module path are the durable indicators** — they survive recompilation
of unrelated code and will match sibling binaries from the same tree.

### String indicators

```
minisocket/cmd/mini-nc
/src/internal/proto/proto.go
/src/internal/crypto/crypto.go
MINISOCKET NC
Community Edition
Session rejected (no matching host for this secret)
no secret provided (use -s or -k)
session not ready
write encrypted handshake:
seal payload:
OFFLINE: timeout
ONLINE(
MINI_HOST
MINI_PORT
```

### Environment variables

```
MINI_HOST    MINI_PORT
```

---

## 11. Detection & Response

### Hunting

1. **YARA** on the Go BuildID and the `minisocket/` module path — highest fidelity, and
   catches the implant and relay from the same build tree.
2. **Sweep for sibling binaries.** The `cmd/` + `internal/` layout guarantees they exist.
   Search filesystems for the `minisocket` module string, not just this hash.
3. **Process telemetry:** any process spawning `bash --norc --noprofile` or
   `sh --norc --noprofile` where the parent is not a known shell/terminal emulator.
4. **Environment telemetry:** processes with `MINI_HOST` or `MINI_PORT` set.
5. **Command-line telemetry:** `-s` with a high-entropy argument alongside `-t`/`-e`.
   Note `-k FILE` is designed to defeat exactly this — do not rely on it alone.
6. **Netflow:** long-lived outbound TCP with low-volume bidirectional keystroke-cadence
   traffic to a non-standard port, no TLS handshake, high payload entropy.

### Response priorities

1. **Determine direction.** This is the *operator* console. Establish whether this host
   is an attacker's staging box, a pivot, or a legitimate red-team workstation.
2. **Recover the secret.** Check argv history, shell history, and any `-k` key file. The
   secret is the rendezvous ID — it identifies **which** implants this console controls.
3. **Hunt the implants.** The secret plus the relay address scopes the victim fleet.
4. **Assume shell-history evasion.** With `-n`/`-R`/`-P`, operator activity on victim
   hosts will **not** appear in `.bash_history`. Pivot to auditd/eBPF `execve` telemetry,
   PTY records, and network logs instead.
5. **Preserve** the binary and any key files before remediation.

### MITRE ATT&CK

| ID | Technique |
|---|---|
| T1219 | Remote Access Software |
| T1090 | Proxy (relay/rendezvous C2) |
| T1090.002 | External Proxy |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography (X25519) |
| T1573.001 | Encrypted Channel: Symmetric Cryptography (AES-GCM) |
| T1571 | Non-Standard Port |
| T1059.004 | Command and Scripting Interpreter: Unix Shell |
| T1562.003 | Impair Defenses: Impair Command History Logging (`--norc --noprofile`) |
| T1027 | Obfuscated Files or Information (`XORMask`, stripped binary) |
| T1008 | Fallback Channels (auto-reconnect) |
