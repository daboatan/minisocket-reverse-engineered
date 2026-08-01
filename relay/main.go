// minisocket-relay is a lightweight rendezvous relay for the minisocket toolkit.
// It pairs operator consoles (mini-nc) with implants (mini-socket) that share
// the same pre-shared secret. The relay is blind — it never decrypts traffic.
//
// Architecture inspired by gsocket-relay but simplified for Go:
//
//	https://github.com/hackerschoice/gsocket-relay
//
// Protocol:
//  1. Each peer connects and sends a 32-byte masked SHA-256(secret) prefix.
//  2. The relay reads these 32 bytes and derives a session ID.
//  3. Peers with matching session IDs are paired.
//  4. Once paired, the relay bidirectionally pipes raw bytes between them.
//  5. The relay never reads or decrypts the AES-GCM payload.
//
// Build: CGO_ENABLED=0 go build -ldflags="-s -w" ./relay
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	defaultPort         = 443
	prefixLen           = 32 // SHA-256 output = 32 bytes
	handshakeTimeout    = 10 * time.Second
	idleTimeout         = 2 * time.Hour
	cleanupInterval     = 60 * time.Second
	maxPendingPerSecret = 10
)

// pendingPeer represents a connected peer waiting to be paired.
type pendingPeer struct {
	conn      net.Conn
	prefix    [prefixLen]byte
	createdAt time.Time
}

// session represents a paired operator + implant tunnel.
type session struct {
	operator net.Conn
	implant  net.Conn
	created  time.Time
	bytesIn  int64
	bytesOut int64
	mu       sync.Mutex
}

// relay is the main relay state.
type relay struct {
	mu       sync.Mutex
	pending  map[string][]*pendingPeer // keyed by session ID (hex)
	sessions map[string]*session       // keyed by session ID (hex)
	started  time.Time
}

func main() {
	port := flag.Int("p", defaultPort, "TCP listening port")
	verbose := flag.Bool("v", false, "Verbose logging")
	flag.Parse()

	if !*verbose {
		log.SetFlags(0)
	}

	r := &relay{
		pending:  make(map[string][]*pendingPeer),
		sessions: make(map[string]*session),
		started:  time.Now(),
	}

	addr := fmt.Sprintf(":%d", *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen(%s): %v", addr, err)
	}
	log.Printf("[relay] listening on :%d", *port)

	// Graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("[relay] shutting down...")
		ln.Close()
		r.shutdown()
		os.Exit(0)
	}()

	// Periodic cleanup of stale pending peers and idle sessions.
	go r.cleanupLoop()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return
			}
			log.Printf("[relay] accept: %v", err)
			continue
		}
		go r.handleConn(conn)
	}
}

// handleConn reads the handshake prefix and attempts to pair the peer.
func (r *relay) handleConn(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()

	// Set a deadline for reading the prefix.
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))

	var prefix [prefixLen]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		log.Printf("[relay] %s — prefix read failed: %v", remoteAddr, err)
		conn.Close()
		return
	}

	// Clear the deadline — connection is now in relay mode.
	conn.SetReadDeadline(time.Time{})

	// Derive session ID from the prefix (the prefix itself IS the session ID).
	sessionID := string(prefix[:])

	r.mu.Lock()

	// Check if there's already a pending peer with this session ID.
	pending, exists := r.pending[sessionID]

	if !exists || len(pending) == 0 {
		// First peer for this session ID — wait for a partner.
		if len(pending) >= maxPendingPerSecret {
			log.Printf("[relay] %s — too many pending for session %x, rejecting", remoteAddr, prefix[:8])
			r.mu.Unlock()
			conn.Close()
			return
		}
		r.pending[sessionID] = append(r.pending[sessionID], &pendingPeer{
			conn:      conn,
			prefix:    prefix,
			createdAt: time.Now(),
		})
		r.mu.Unlock()
		log.Printf("[relay] %s — waiting (session %x...)", remoteAddr, prefix[:8])
		return
	}

	// Found a match! Pair them.
	partner := pending[0]
	r.pending[sessionID] = pending[1:]

	// Clean up if this was the last pending.
	if len(r.pending[sessionID]) == 0 {
		delete(r.pending, sessionID)
	}

	sess := &session{
		operator: conn, // The connecting peer is treated as operator
		implant:  partner.conn,
		created:  time.Now(),
	}
	r.sessions[sessionID] = sess
	r.mu.Unlock()

	log.Printf("[relay] %s <-> %s — paired (session %x...)", remoteAddr, partner.conn.RemoteAddr(), prefix[:8])

	// Start bidirectional relay.
	r.relayPair(sess, sessionID)
}

// relayPair bidirectionally copies data between two paired connections.
func (r *relay) relayPair(sess *session, sessionID string) {
	var wg sync.WaitGroup
	wg.Add(2)

	// conn (operator) → partner (implant).
	go func() {
		defer wg.Done()
		n, _ := io.Copy(sess.implant, sess.operator)
		sess.mu.Lock()
		sess.bytesIn += n
		sess.mu.Unlock()
		// Signal EOF to the other side.
		if tcpConn, ok := sess.implant.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// partner (implant) → conn (operator).
	go func() {
		defer wg.Done()
		n, _ := io.Copy(sess.operator, sess.implant)
		sess.mu.Lock()
		sess.bytesOut += n
		sess.mu.Unlock()
		if tcpConn, ok := sess.operator.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()

	// Clean up session.
	sess.operator.Close()
	sess.implant.Close()

	r.mu.Lock()
	delete(r.sessions, sessionID)
	r.mu.Unlock()

	log.Printf("[relay] session %x... closed (in=%d out=%d)", []byte(sessionID[:8]), sess.bytesIn, sess.bytesOut)
}

// cleanupLoop periodically removes stale pending peers and idle sessions.
func (r *relay) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		r.mu.Lock()

		// Remove pending peers older than handshake timeout.
		for id, peers := range r.pending {
			var kept []*pendingPeer
			for _, p := range peers {
				if time.Since(p.createdAt) > handshakeTimeout {
					log.Printf("[relay] %s — pending timed out (session %x...)", p.conn.RemoteAddr(), p.prefix[:8])
					p.conn.Close()
				} else {
					kept = append(kept, p)
				}
			}
			if len(kept) == 0 {
				delete(r.pending, id)
			} else {
				r.pending[id] = kept
			}
		}

		// Remove idle sessions.
		for id, sess := range r.sessions {
			if time.Since(sess.created) > idleTimeout {
				log.Printf("[relay] session %x... — idle timeout", []byte(id[:8]))
				sess.operator.Close()
				sess.implant.Close()
				delete(r.sessions, id)
			}
		}

		active := len(r.sessions)
		pending := 0
		for _, peers := range r.pending {
			pending += len(peers)
		}

		r.mu.Unlock()

		if active > 0 || pending > 0 {
			log.Printf("[relay] stats: %d active, %d pending, uptime %s", active, pending, time.Since(r.started).Round(time.Second))
		}
	}
}

// shutdown gracefully closes all connections.
func (r *relay) shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, peers := range r.pending {
		for _, p := range peers {
			p.conn.Close()
		}
	}
	for _, sess := range r.sessions {
		sess.operator.Close()
		sess.implant.Close()
	}
	r.pending = nil
	r.sessions = nil
}
