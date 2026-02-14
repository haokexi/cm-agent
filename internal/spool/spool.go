package spool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Spool stores already-snappy-compressed remote_write payloads on disk for later replay.
// File format:
// - uvarint: series count (best-effort bookkeeping)
// - bytes: snappy payload
type Spool struct {
	dir      string
	maxBytes int64
	maxFiles int
}

type Entry struct {
	Path   string
	Bytes  int64
	Series int
}

func New(dir string, maxBytes int64, maxFiles int) (*Spool, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("spool dir is required")
	}
	if maxBytes <= 0 {
		return nil, errors.New("spool maxBytes must be > 0")
	}
	if maxFiles <= 0 {
		maxFiles = 1000
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Spool{dir: dir, maxBytes: maxBytes, maxFiles: maxFiles}, nil
}

func (s *Spool) Add(series int, payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", nil
	}

	// Worst-case encoded size: varint(10) + payload.
	if int64(len(payload))+16 > s.maxBytes {
		return "", fmt.Errorf("payload too large for spool maxBytes=%d payloadBytes=%d", s.maxBytes, len(payload))
	}

	tmp := filepath.Join(s.dir, fmt.Sprintf(".tmp_%d_%08x", time.Now().UnixNano(), rand.Uint32()))
	final := filepath.Join(s.dir, fmt.Sprintf("%019d_%08x.rw", time.Now().UnixNano(), rand.Uint32()))

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(series))
	if _, err := f.Write(buf[:n]); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if _, err := f.Write(payload); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return "", err
	}

	_ = s.enforceLimits()
	return final, nil
}

func (s *Spool) List() ([]Entry, int64, error) {
	des, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, 0, err
	}
	var entries []Entry
	var total int64
	for _, de := range des {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if !strings.HasSuffix(name, ".rw") {
			continue
		}
		p := filepath.Join(s.dir, name)
		fi, err := de.Info()
		if err != nil {
			continue
		}
		entries = append(entries, Entry{Path: p, Bytes: fi.Size()})
		total += fi.Size()
	}
	sort.Slice(entries, func(i, j int) bool {
		// filename starts with unixnano so lexicographic is chronological
		return filepath.Base(entries[i].Path) < filepath.Base(entries[j].Path)
	})
	return entries, total, nil
}

func (s *Spool) Read(path string) (series int, payload []byte, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, nil, err
	}
	seriesU, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, nil, errors.New("invalid spool entry header")
	}
	return int(seriesU), b[n:], nil
}

func (s *Spool) Delete(path string) error {
	return os.Remove(path)
}

func (s *Spool) enforceLimits() error {
	entries, total, err := s.List()
	if err != nil {
		return err
	}
	// Enforce maxFiles first, then maxBytes.
	for len(entries) > s.maxFiles {
		_ = os.Remove(entries[0].Path)
		total -= entries[0].Bytes
		entries = entries[1:]
	}
	for total > s.maxBytes && len(entries) > 0 {
		_ = os.Remove(entries[0].Path)
		total -= entries[0].Bytes
		entries = entries[1:]
	}
	return nil
}

// CopyN is a small helper for streaming reads if needed later.
func CopyN(dst io.Writer, src io.Reader, n int64) (int64, error) {
	return io.CopyN(dst, src, n)
}
