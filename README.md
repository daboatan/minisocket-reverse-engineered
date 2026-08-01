# minisocket — Reverse-Engineered Go Project

Reverse-engineered from a stripped `mini-nc` ELF binary (Go 1.22.12, linux/amd64). This is the **operator-side console** of a custom remote-access toolkit that uses a relay/rendezvous server, pre-shared secret authentication, and X25519 + AES-256-GCM end-to-end encryption.

**This project was reconstructed entirely from static analysis** — the binary was never executed.

---

## Project Layout

```
minisocket/
├── cmd/mini-nc/main.go          # Operator CLI — the `mini-nc` binary
├── internal/
│   ├── proto/proto.go           # Wire protocol: framing, ECDH, XOR masking
│   └── crypto/crypto.go         # AES-GCM encryption + PBKDF2 key derivation
├── go.mod
├── README.md
├── mini-nc                      # Original binary (reference)
└── mini-nc-analysis.md          # Full static analysis report
```

### Package `internal/crypto`

| Function | Role |
|----------|------|
| `SHA256Digest` | SHA-256 hash → 32-byte session ID from secret |
| `DeriveKey` | PBKDF2 over shared secret → AES-256 key |
| `Encrypt` | AES-256-GCM encrypt with random 12-byte nonce |
| `Decrypt` | AES-256-GCM decrypt |

### Package `internal/proto`

| Function | Role |
|----------|------|
| `GenerateECDH` | X25519 ephemeral keypair |
| `SharedSecret` | X25519 ECDH shared secret |
| `MaskSecret` / `XORMask` | XOR obfuscation of wire handshake prefix |
| `SealPayload` | Encrypt payload for wire transmission |
| `(*PacketHeader).Write` | Write 5-byte frame header |
| `ReadHeader` | Read 5-byte frame header |
| `ReadFull` | Read length-framed payload |

---

## Protocol Summary

```
Operator                          Relay                         Implant
   |                                |                               |
   |-- XOR-masked(SHA256(secret)) ->|                               |
   |-- Encrypted(X25519 pubkey)  -->|                               |
   |                                |<-- relay pairs by session ID  |
   |<-- Encrypted(X25519 pubkey) ---|                               |
   |                                |                               |
   |<====== AES-256-GCM channel ========> (end-to-end, relay blind) |
```

1. Secret → SHA-256 → **session ID** → XOR-masked → sent as wire prefix
2. X25519 ECDH handshake, encrypted with a key derived from the secret
3. Session key = PBKDF2(shared_secret)
4. All subsequent packets: 5-byte header `[uint32 len][uint8 type]` + AES-256-GCM payload

---

## Build

```bash
# Requires Go 1.22+
go mod tidy
CGO_ENABLED=0 go build -ldflags="-s -w" -o mini-nc ./cmd/mini-nc
```

For a static binary matching the original:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o mini-nc ./cmd/mini-nc
```

---

## Usage

```
  Usage: mini-nc [options] [relay-host]
  Options:
    -s SECRET    Secret key
    -k FILE      Read secret from file
    -p PORT      Relay port (default 5555)
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
  Environment:
    MINI_PORT    Override relay port
    MINI_HOST    Override relay host
```

---

## Analysis Caveats

Values marked with `*` are plausible reconstructions — the originals require full disassembly to recover:

| Item | Status |
|------|--------|
| Default relay port (5555) | *Guessed |
| XOR mask key (`0x5a,0xa5,0x3c,0xc3,...`) | *Guessed |
| PBKDF2 salt (`minisocket-v1-kdf`) | *Guessed |
| PBKDF2 iterations (100,000) | *Guessed |
| Packet type opcodes | *Inferred from string context |
| All function signatures, package layout, wire protocol design | Verified from `.gopclntab` and `.rodata` |

---

## Missing Sibling Binaries

The `cmd/mini-nc` + `internal/` layout implies sibling binaries built from the same module:

- **Implant** (victim-side agent)
- **Relay server** (rendezvous broker)

These were **not** provided with the sample. Hunt for them using the `minisocket` module path string and the Go BuildID:

```
Go BuildID: pW94Jp15b9QJyxylz5Fh/LH3QD8lMP8XeS26IBukm/Q6HV7UxzFpJ9pgQK-X04/Sy8sXhTxLjtLMnDp5T5S
```

---

## Disclaimer

This project is a **reverse-engineering artifact** produced for analysis and research purposes. The original binary is classified as malicious-capable remote-access tooling. Do not deploy or connect to untrusted infrastructure.
