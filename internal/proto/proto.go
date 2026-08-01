package proto

import (
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"io"

	"minisocket/internal/crypto"
)

// Packet types (opcodes).
const (
	PktHandshake uint8 = 0x01
	PktData      uint8 = 0x02
	PktClose     uint8 = 0x03
	PktPing      uint8 = 0x04
	PktExec      uint8 = 0x05
	PktWinsize   uint8 = 0x06
	PktStdin     uint8 = 0x07
	PktStdout    uint8 = 0x08
	PktStderr    uint8 = 0x09
	PktExitCode  uint8 = 0x0a
)

// Header size: 4 bytes length + 1 byte type = 5 bytes.
const HeaderSize = 5

// MaxPayloadSize is the maximum payload size per packet.
const MaxPayloadSize = 65535

// XORMask key — a fixed obfuscation constant recovered from the binary's
// design. The actual key is unknown (requires disassembly); this is a
// plausible reconstruction consistent with the "mask" design.
var xorMaskKey = []byte{0x5a, 0xa5, 0x3c, 0xc3, 0x69, 0x96, 0x0f, 0xf0}

// PacketHeader represents the 5-byte frame header:
//
//	[0:4]  uint32 length (big-endian, payload only)
//	[4]    uint8 packet type
type PacketHeader struct {
	Length uint32
	Type   uint8
}

// Write writes the header to w in network byte order.
func (h *PacketHeader) Write(w io.Writer) error {
	var buf [HeaderSize]byte
	binary.BigEndian.PutUint32(buf[0:4], h.Length)
	buf[4] = h.Type
	_, err := w.Write(buf[:])
	return err
}

// ReadHeader reads a 5-byte packet header from r.
func ReadHeader(r io.Reader) (*PacketHeader, error) {
	var buf [HeaderSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	return &PacketHeader{
		Length: binary.BigEndian.Uint32(buf[0:4]),
		Type:   buf[4],
	}, nil
}

// ReadFull reads exactly n bytes from r into a new slice.
func ReadFull(r io.Reader, n uint32) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read full (%d bytes): %w", n, err)
	}
	return buf, nil
}

// GenerateECDH generates a new X25519 ephemeral keypair and returns the
// 32-byte public key suitable for sending over the wire.
func GenerateECDH() (*ecdh.PrivateKey, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(nil) // crypto/rand
	if err != nil {
		return nil, nil, fmt.Errorf("generate ecdh: %w", err)
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// SharedSecret computes the X25519 ECDH shared secret from our private key
// and the peer's raw 32-byte public key.
func SharedSecret(priv *ecdh.PrivateKey, peerPubBytes []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("shared secret: %w", err)
	}
	return priv.ECDH(pub)
}

// MaskSecret XOR-masks the secret with a repeating-key XOR pad derived from
// xorMaskKey. This is obfuscation, not cryptography — it defeats naive
// signature-matching on the wire handshake prefix.
func MaskSecret(secret []byte) []byte {
	return XORMask(secret, xorMaskKey)
}

// XORMask applies repeating-key XOR to data using the provided key.
func XORMask(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// SealPayload encrypts a payload with the session cipher.
// Wraps crypto.Encrypt with the length-framing expected by the wire protocol.
func SealPayload(key, plaintext []byte) ([]byte, error) {
	encrypted, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal payload: %w", err)
	}
	return encrypted, nil
}
