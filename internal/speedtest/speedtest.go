// Package speedtest implements a pure-Go TCP bandwidth measurement tool,
// replacing the dependency on iperf3.
//
// Protocol (simple, no negotiation):
//  1. Server listens on a TCP port.
//  2. Client connects N parallel streams.
//  3. Each stream sends a 1-byte header: 'S' = client sends (upload), 'R' = client receives (download).
//  4. The sending side writes random-filled blocks as fast as possible.
//  5. The receiving side counts bytes and discards the data.
//  6. After the duration expires, connections are closed and byte counts are tallied.
package speedtest

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const blockSize = 128 * 1024 // 128 KiB write blocks

// IntervalReport is emitted once per second during the test.
type IntervalReport struct {
	IntervalStart float64 // seconds since test start
	IntervalEnd   float64
	Bytes         int64
	BitsPerSec    float64
}

// Result is the final outcome of a single-direction test.
type Result struct {
	Success    bool
	Error      string
	TotalBytes int64
	BitsPerSec float64
	Duration   time.Duration
}

// --- Server ---

// Server listens on a TCP port and handles exactly one test session (like iperf3 -s -1).
// It returns after all client streams disconnect or the context is cancelled.
func RunServer(ctx context.Context, port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("listen :%d: %w", port, err)
	}
	defer ln.Close()

	// Close listener when context is cancelled.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// Accept connections until the first one closes, then wait for the rest.
	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Context cancelled or listener closed — done accepting.
			break
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			handleServerConn(ctx, c)
		}(conn)
	}
	wg.Wait()
	return nil
}

func handleServerConn(ctx context.Context, conn net.Conn) {
	// Read 1-byte direction header.
	header := make([]byte, 1)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}

	switch header[0] {
	case 'S':
		// Client is sending → server receives (discard).
		buf := make([]byte, blockSize)
		for {
			if ctx.Err() != nil {
				return
			}
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	case 'R':
		// Client wants to receive → server sends.
		buf := makeRandomBlock()
		for {
			if ctx.Err() != nil {
				return
			}
			if _, err := conn.Write(buf); err != nil {
				return
			}
		}
	}
}

// --- Client ---

// RunClient connects to the server and performs a bandwidth test.
// If reverse is true, the server sends data to the client (download test).
// onInterval is called once per second with an interval report (may be nil).
func RunClient(
	ctx context.Context,
	host string,
	port int,
	duration time.Duration,
	parallel int,
	reverse bool,
	onInterval func(IntervalReport),
) Result {
	if parallel <= 0 {
		parallel = 1
	}

	// Per-stream byte counter.
	counters := make([]*atomic.Int64, parallel)
	for i := range counters {
		counters[i] = &atomic.Int64{}
	}

	// Direction header: 'S' = client sends, 'R' = client receives (server sends).
	var dirByte byte = 'S'
	if reverse {
		dirByte = 'R'
	}

	// Connect all streams.
	addr := fmt.Sprintf("%s:%d", host, port)
	conns := make([]net.Conn, 0, parallel)
	for i := 0; i < parallel; i++ {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			// Close any already-opened connections.
			for _, c := range conns {
				c.Close()
			}
			return Result{Error: fmt.Sprintf("connect stream %d: %s", i, err)}
		}
		// Send direction header.
		if _, err := conn.Write([]byte{dirByte}); err != nil {
			conn.Close()
			for _, c := range conns {
				c.Close()
			}
			return Result{Error: fmt.Sprintf("write header stream %d: %s", i, err)}
		}
		conns = append(conns, conn)
	}

	testCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	// Launch data transfer goroutines.
	var wg sync.WaitGroup
	for i, conn := range conns {
		wg.Add(1)
		if reverse {
			go func(c net.Conn, ctr *atomic.Int64) {
				defer wg.Done()
				receiveLoop(testCtx, c, ctr)
			}(conn, counters[i])
		} else {
			go func(c net.Conn, ctr *atomic.Int64) {
				defer wg.Done()
				sendLoop(testCtx, c, ctr)
			}(conn, counters[i])
		}
	}

	// Interval reporting (every 1 second).
	start := time.Now()
	var prevBytes int64
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

loop:
	for {
		select {
		case <-done:
			break loop
		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(start).Seconds()
			var total int64
			for _, c := range counters {
				total += c.Load()
			}
			intervalBytes := total - prevBytes
			intervalSec := 1.0
			if onInterval != nil {
				onInterval(IntervalReport{
					IntervalStart: elapsed - intervalSec,
					IntervalEnd:   elapsed,
					Bytes:         intervalBytes,
					BitsPerSec:    float64(intervalBytes) * 8 / intervalSec,
				})
			}
			prevBytes = total
		}
	}

	// Close all connections.
	for _, c := range conns {
		c.Close()
	}

	// Final tally.
	totalElapsed := time.Since(start)
	var totalBytes int64
	for _, c := range counters {
		totalBytes += c.Load()
	}

	secs := totalElapsed.Seconds()
	if secs <= 0 {
		secs = 1
	}

	return Result{
		Success:    true,
		TotalBytes: totalBytes,
		BitsPerSec: float64(totalBytes) * 8 / secs,
		Duration:   totalElapsed,
	}
}

func sendLoop(ctx context.Context, conn net.Conn, counter *atomic.Int64) {
	buf := makeRandomBlock()
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := conn.Write(buf)
		if n > 0 {
			counter.Add(int64(n))
		}
		if err != nil {
			return
		}
	}
}

func receiveLoop(ctx context.Context, conn net.Conn, counter *atomic.Int64) {
	buf := make([]byte, blockSize)
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := conn.Read(buf)
		if n > 0 {
			counter.Add(int64(n))
		}
		if err != nil {
			return
		}
	}
}

func makeRandomBlock() []byte {
	buf := make([]byte, blockSize)
	rand.Read(buf)
	return buf
}
