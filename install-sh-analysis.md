# Malware Analysis Report — `install.sh` (minisocket Deployer)

**Analyst:** GitHub Copilot
**Date:** 2026-08-02
**Sample:** `/home/atandabo/apps/minisocket/install.sh`
**Analysis type:** Static only — **the script was never executed**

---

## 1. Executive Summary

`install.sh` is the **deployment and persistence orchestrator** for the minisocket
remote-access toolkit. It is a 1019-line POSIX shell script that:

1. Downloads the implant binary from GitHub Releases (or a direct `minisocket.io` URL)
2. Generates a per-machine pre-shared secret
3. Installs the implant as a stealth-named system service or user-land persistence
4. Exfiltrates the secret + host metadata to a Telegram bot
5. Deploys up to **14 layered persistence mechanisms** for root installs
6. Includes a **memfd_create noexec bypass** for hardened systems

The script is versioned `v0.5` and self-describes as "Community Edition" tooling.
It is purpose-built for mass deployment across heterogeneous Linux fleets (kernel
2.6+, any init system, 11 CPU architectures).

**Verdict:** Malicious implant deployment and persistence orchestrator.
**Confidence:** High.

---

## 2. File Identification

| Property | Value |
|---|---|
| Filename | `install.sh` |
| Size | 1019 lines (~35 KB) |
| Type | POSIX `/bin/sh` shell script |
| Declared version | `v0.5` |
| Resolved release | `v0.3` (from `minisocket/minisocket` GitHub) |

### Hashes

```
SHA-256  7de6f0666d39b5003306f5a86d1abed7a737d14e71059784ea1dc1e848ad93cf
```

---

## 3. Architecture & Compatibility Matrix

The script targets **11 CPU architectures** with pre-built Go static binaries:

| `uname -m` | Canonical name | Binary filename pattern |
|---|---|---|
| `x86_64`, `amd64` | `x86_64` | `mini-socket_linux-x86_64` |
| `aarch64`, `arm64` | `aarch64` | `mini-socket_linux-aarch64` |
| `armv7*`, `armhf` | `armv7` | `mini-socket_linux-armv7` |
| `i386`–`i686` | `i386` | `mini-socket_linux-i386` |
| `mips64el` | `mips64le` | `mini-socket_linux-mips64le` |
| `mips64` | `mips64` | `mini-socket_linux-mips64` |
| `mipsel` | `mipsle` | `mini-socket_linux-mipsle` |
| `mips` | `mips` | `mini-socket_linux-mips` |
| `ppc64le` | `ppc64le` | `mini-socket_linux-ppc64le` |
| `riscv64` | `riscv64` | `mini-socket_linux-riscv64` |
| `s390x` | `s390x` | `mini-socket_linux-s390x` |

This covers: cloud VMs (x86_64, aarch64), embedded/IoT (armv7, mips*), mainframes
(s390x), and emerging platforms (riscv64). The breadth is characteristic of
commodity botnet/APT deployment tooling targeting **maximum heterogeneity**.

### Init system detection (6 targets)

The script probes PID 1 and filesystem markers in priority order:

```
systemd → sysvinit → openrc → upstart → rc.local → cron
```

A dedicated service installer exists for each init type. The **cron fallback** is
universal — if nothing else matches, a `* * * * *` watchdog crontab runs the implant
every minute, re-spawning if the process is absent.

---

## 4. Infrastructure & C2

### Download sources

| URL | Purpose | Transport |
|---|---|---|
| `https://github.com/minisocket/minisocket/releases/download/v0.3/mini-socket_linux-{ARCH}` | Primary binary download | HTTPS |
| `https://minisocket.io/bin/mini-socket` | Memfd bypass download (direct URL) | HTTPS |

The script uses `curl`, `wget`, or `fetch` — whichever is available — with a
120-second timeout and `--no-check-certificate` on `wget`.

### Telegram exfiltration

The secret and host metadata are exfiltrated via the Telegram Bot API:

```
POST https://api.telegram.org/bot{MINI_TG_TOKEN}/sendMessage
```

Exfiltrated data in each message:
- Hostname
- Public IP (from `ifconfig.me`)
- OS / kernel version
- Init system type
- Generated secret key

Two environment variables control this:
- `MINI_TG_TOKEN` — Telegram bot token
- `MINI_TG_CHAT` — Telegram chat ID

If either is unset, Telegram exfiltration is silently disabled. This is a
**dual-use design**: with TG creds it's an automated callback; without them the
operator reads the secret from the install output.

### Default relay port

The memfd bypass hardcodes `MINI_PORT=443` — using a common HTTPS port for the
custom binary protocol, blending with outbound web traffic.

---

## 5. Stealth & Evasion Techniques

### 5.1 Process name masquerading (~30 kernel-thread names)

```
kworker ksoftirqd migration watchdog cpuhp netns rcu_sched
kdevtmpfs khungtaskd oom_reaper writeback kcompactd0 ksmd khugepaged
kintegrityd kblockd edac-poller devfreq_wq kswapd0 kthrotld irq_work
acpi_thermal scsi_tmf dm_bufio ipv6_addrconf systemd-logind dbus-daemon
polkitd thermald accounts-daemon rsyslogd atd
```

The binary is renamed to a randomly selected kernel-thread or daemon name.
When running as a systemd service, it wraps the name in brackets `[kworker]`
(via `exec -a`) to mimic kernel threads in `ps` output.

### 5.2 Directory camouflage (~30 common dot-directories)

```
.aws .ssh .config .cache .local .kube .docker .ansible .npm
.composer .gnupg .mozilla .vscode .vim .terraform .jenkins .git .azure
.pki .yarn .pip .gem .m2 .gradle .cargo .nuget .certbot
```

The implant is installed inside `$HOME/{random_dir}/{stealth_name}/` —
e.g. `~/.kube/kswapd0/kswapd0`. These paths look legitimate under casual inspection.

### 5.3 Secret file obfuscation (root installs)

The generated secret is stored with **defense-in-depth concealment**:

1. Path: `/usr/lib/x86_64-linux-gnu/.libsystemd-shared-249.so.cache` — mimics a
   systemd shared-library cache file
2. Content: XOR-obfuscated via `xxd -p` hex encoding
3. Permissions: `chmod 000` — no read/write/execute for anyone
4. Immutable: `chattr +i` if available — prevents even root from deleting/modifying
5. Timestomp: `touch -r` to backdate the file to match `libc.so.6` or `/etc/passwd`

The decode command (`xxd -r -p`) is embedded in every persistence trigger, so the
secret remains recoverable by the watchdog scripts.

### 5.4 noexec bypass via memfd_create

If all writable directories (`/tmp`, `/dev/shm`, `/var/tmp`, `$HOME`, `/run`) are
mounted `noexec`, the script falls back to **fileless execution**:

1. Downloads the binary via `curl` piped to `perl`
2. Calls `memfd_create` syscall (with architecture-specific syscall numbers:
   319=x86_64, 279=aarch64, 385=i386/arm)
3. Writes the binary into the anonymous memory file descriptor
4. Executes via `/proc/$$/fd/{fd}`

The binary never touches disk. This defeats `noexec` mounts, filesystem-based AV
scanning, and forensic file recovery.

### 5.5 Service unit stealth (systemd)

- `StandardOutput=null` / `StandardError=null` — no journald logging of stdout/stderr
- `Restart=always` with `RestartSec=30` — resilient to kill attempts
- Description uses the stealth name, blending with real system services

---

## 6. Persistence Matrix

### Root persistence (14 mechanisms)

| # | Mechanism | Trigger | File/Path |
|---|---|---|---|
| 1 | cron (crontab) | Every 5 min | `crontab -l` |
| 2 | `/etc/cron.d/` | Every 7 min | `/etc/cron.d/{stealth}` |
| 3 | systemd timer | Boot + every 5 min | `/etc/systemd/system/{stealth}.(service\|timer)` |
| 4 | init.d script | Boot (runlevel 2-5) | `/etc/init.d/{stealth}` |
| 5 | rc.local | Boot | `/etc/rc.local` |
| 6 | profile.d | User login | `/etc/profile.d/{stealth}.sh` |
| 7 | bash.bashrc | User shell | `/etc/bash.bashrc` |
| 8 | modprobe.d hook | Kernel module load | `/etc/modprobe.d/{stealth}.conf` |
| 9 | NetworkManager dispatcher | Network up | `/etc/NetworkManager/dispatcher.d/99-{stealth}` |
| 10 | if-up.d | Network up (Debian) | `/etc/network/if-up.d/{stealth}` |
| 11 | udev rules | Device add (net subsystem) | `/etc/udev/rules.d/99-{stealth}.rules` |
| 12 | logrotate.d hook | Daily (log rotation) | `/etc/logrotate.d/{stealth}` |
| 13 | apt hook | Package operations | `/etc/apt/apt.conf.d/99{stealth}` |
| 14 | motd.d | SSH login | `/etc/update-motd.d/99-{stealth}` |

Every watchdog script includes a `pgrep` check — it only spawns the implant if no
instance is already running. This prevents process storms while ensuring resilience.

The persistence methods cover **boot, cron, login, network events, kernel events,
package management, and log rotation** — there is no single removal vector.

### User persistence (4 mechanisms)

| # | Mechanism | Trigger |
|---|---|---|
| 1 | `.bashrc` | Shell start |
| 2 | `.profile` | Login shell |
| 3 | crontab (`*/5 * * * *`) | Every 5 min |
| 4 | `.config/autostart/*.desktop` | Desktop login |

The cron entry is base64-encoded to avoid trivial `grep` detection:
```
echo {base64_payload} | base64 -d | sh
```

### Cross-init redundancy

Even when a primary init system is detected and used, the script adds:
- A **backup cron watchdog** (if cron wasn't the primary)
- An **rc.local entry** (if rc.local wasn't the primary)

This ensures survival across init system transitions or partial cleanup.

---

## 7. Operational Flow

```
install.sh execution
  │
  ├─ 1. Detect architecture (11 targets)
  ├─ 2. Detect init system (6 targets)
  ├─ 3. Download implant binary (GitHub Releases)
  ├─ 4. Binary verification (size > 1MB + execution test)
  │     └─ On noexec: memfd_create bypass via perl
  ├─ 5. Generate per-host secret (from binary's -g flag)
  ├─ 6. [root] Install as stealth-named system service + 14 persistence hooks
  ├─ 7. [user] Install in camouflaged dot-directory + 4 persistence hooks
  ├─ 8. Exfiltrate secret + host metadata to Telegram
  └─ 9. Start implant immediately, clean up temp files
```

---

## 8. Indicators of Compromise

### File artifacts

```
SHA-256  7de6f0666d39b5003306f5a86d1abed7a737d14e71059784ea1dc1e848ad93cf  install.sh
```

### Download URLs

```
https://github.com/minisocket/minisocket/releases/download/v0.3/mini-socket_linux-{ARCH}
https://minisocket.io/bin/mini-socket
```

### Secret file patterns (root)

```
/usr/lib/x86_64-linux-gnu/.libsystemd-shared-249.so.cache
/lib/x86_64-linux-gnu/.libsystemd-shared-249.so.cache
/usr/lib/.libsystemd-shared-249.so.cache
/lib/.libsystemd-shared-249.so.cache
```

Files with `chmod 000` + `chattr +i` in library paths.

### Process indicators

Any process named after a kernel thread (`kworker`, `ksoftirqd`, etc.) that:
- Is **not** PID 2 or a child of `kthreadd`
- Has brackets in `ps` output like `[kworker]` (real kernel threads use `[kworker/0:1]`)
- Has a userspace binary path (`/usr/bin/kworker` — kernel threads have no path)
- Has a parent that is not `kthreadd` (PID 2)

### Persistence artifacts

```
/etc/systemd/system/{kworker,ksoftirqd,migration,...}.(service|timer)
/etc/init.d/{stealth_kernel_name}
/etc/cron.d/{stealth_kernel_name}
/etc/profile.d/{stealth_kernel_name}.sh
/etc/modprobe.d/{stealth_kernel_name}.conf
/etc/NetworkManager/dispatcher.d/99-{stealth_name}
/etc/network/if-up.d/{stealth_name}
/etc/udev/rules.d/99-{stealth_name}.rules
/etc/logrotate.d/{stealth_name}
/etc/apt/apt.conf.d/99{stealth_name}
/etc/update-motd.d/99-{stealth_name}
```

### Cron entries

```
*/5 * * * * pgrep -f '{stealth_name}' >/dev/null 2>&1 || MINI_ARGS="-k {key_path}" MINI_PORT={port} {binary_path} -d # {stealth_name}
* * * * * pgrep -f '{stealth_name}' >/dev/null 2>&1 || ... # {stealth_name}
```

### Base64-encoded persistence (user)

Look for base64 strings in `.bashrc` / `.profile` that decode to shell commands
containing `pgrep`, `MINI_ARGS`, and a binary path in a hidden subdirectory of a
common dot-directory.

### Environment variables

```
MINI_TG_TOKEN    MINI_TG_CHAT    MINI_PORT    MINI_HOST
```

### Telegram API calls

Outbound HTTPS to `api.telegram.org/bot{token}/sendMessage` from non-browser
processes (curl/wget).

---

## 9. MITRE ATT&CK

| ID | Technique | Evidence |
|---|---|---|
| T1204.002 | User Execution: Malicious File | Shell script delivery |
| T1543.002 | Create/Modify System Process: systemd | systemd service + timer |
| T1543.001 | Create/Modify System Process: launchd/init | sysvinit, openrc, upstart installers |
| T1053.003 | Scheduled Task/Job: Cron | 4 cron-based persistence paths |
| T1546.004 | Event Triggered Execution: Unix Shell Config | `.bashrc`, `.profile`, `bash.bashrc`, `profile.d` |
| T1546.014 | Event Triggered Execution: Kernel Module Load | modprobe.d hook |
| T1546.016 | Event Triggered Execution: Installer Packages | apt hook |
| T1546.007 | Event Triggered Execution: Netsh/Network | NetworkManager dispatcher, if-up.d, udev net |
| T1546.017 | Event Triggered Execution: udev | udev rules |
| T1547.009 | Boot/Logon Autostart: Shortcut Modification | `.config/autostart/*.desktop` |
| T1036.005 | Masquerading: Match Legitimate Name | 30 kernel-thread names |
| T1564.001 | Hide Artifacts: Hidden Files/Directories | `.dotdir` camouflage, `chmod 000`, `chattr +i` |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Base64-encoded cron payloads |
| T1027.010 | Obfuscated Files: Command Obfuscation | Base64 cron command wrapping |
| T1070.006 | Indicator Removal: Timestomp | `touch -r` to backdate files |
| T1102.002 | Web Service: Bidirectional Communication | GitHub Releases as binary host |
| T1102 | Web Service | Telegram Bot API for exfiltration |
| T1090 | Proxy | Relay C2 via `mini-nc` protocol |
| T1622 | Debugger Evasion | memfd_create noexec bypass |
| T1571 | Non-Standard Port | `MINI_PORT=443` for non-HTTPS protocol |

---

## 10. Analysis Notes

### Binary naming discrepancy

The installer downloads `mini-socket_linux-{ARCH}` (with hyphen), but the companion
`mini-nc` binary was built from module `minisocket/cmd/mini-nc`. This confirms that
the module `minisocket` produces **multiple binaries**:

| Binary | Role | Filename pattern |
|---|---|---|
| `mini-nc` | Operator console | `mini-nc` |
| `mini-socket` | Implant (victim agent) | `mini-socket_linux-{ARCH}` |
| _(unseen)_ | Relay/rendezvous server | Unknown |

### Version mismatch

The script declares `v0.5` but downloads release `v0.3`. This may indicate:
- The installer is versioned independently from the implant
- `v0.3` is the current implant release; `v0.5` is the installer revision
- Or the GitHub releases are lagging behind development

### Telegram dependency

The script **requires** `MINI_TG_TOKEN` and `MINI_TG_CHAT` to be set in the
environment for automated exfiltration. Without these, the operator must manually
copy the secret from the install output. This is a configuration step that may
leave traces in the operator's shell history or deployment wrapper scripts.

### POSIX compatibility

The script avoids bashisms (`[[`, arrays, `==` in `[`, etc.) and uses only POSIX
constructs. This is deliberate for compatibility with minimal/embedded systems
(BusyBox, dash, old `/bin/sh`). The only external dependencies beyond a shell are
`curl`/`wget`/`fetch` (one of three), `perl` (for memfd bypass only), and standard
Unix tools (`pgrep`, `xxd`, `base64`, `chattr`, `touch`).

---

## 11. Response Recommendations

1. **Block download URLs** at the proxy/firewall level:
   - `github.com/minisocket/minisocket/releases/*`
   - `minisocket.io`

2. **Hunt for stealth-named processes** — compare `/proc/*/comm` against the
   STEALTH_NAMES list above. Real kernel threads have PID 2 as parent.

3. **Audit persistence paths** — check all 14 locations listed in §6 for files
   containing `MINI_ARGS`, `MINI_PORT`, `pgrep -f`, or base64-encoded blobs.

4. **Monitor Telegram API calls** — outbound HTTPS to `api.telegram.org` with
   `/sendMessage` from non-browser user agents.

5. **Check for immutable hidden files** in `/usr/lib/` and `/lib/` — `lsattr`
   will reveal `chattr +i` flags regardless of `chmod 000`.

6. **Recover the secret** from any found `{stealth_name}.dat` file — it's a
   22-character plaintext string that identifies **which implant fleet** the
   host belongs to. With the secret + relay address, you can connect to the
   relay and enumerate peer implants.
