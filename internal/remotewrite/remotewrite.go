package remotewrite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
)

// Label is a convenience alias used across this repo.
type Label = prompb.Label

type Config struct {
	URL         string
	BearerToken string
	Timeout     time.Duration

	MaxSeriesPerRequest int
	UserAgent           string
}

type Client struct {
	cfg        Config
	httpClient *http.Client
}

func NewClient(cfg Config) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxSeriesPerRequest <= 0 {
		cfg.MaxSeriesPerRequest = 2000
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "cm-agent"
	}
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

func (c *Client) MaxSeriesPerRequest() int {
	return c.cfg.MaxSeriesPerRequest
}

func (c *Client) Encode(req *prompb.WriteRequest) ([]byte, int, error) {
	if req == nil {
		return nil, 0, errors.New("nil write request")
	}
	if len(req.Timeseries) == 0 {
		return nil, 0, nil
	}
	if strings.TrimSpace(c.cfg.URL) == "" {
		return nil, 0, errors.New("remoteWrite.url is required")
	}

	body, err := req.Marshal()
	if err != nil {
		return nil, 0, fmt.Errorf("marshal WriteRequest: %w", err)
	}
	compressed := snappy.Encode(nil, body)
	return compressed, len(req.Timeseries), nil
}

func (c *Client) Push(ctx context.Context, req *prompb.WriteRequest) (int, error) {
	compressed, series, err := c.Encode(req)
	if err != nil {
		return 0, err
	}
	if len(compressed) == 0 {
		return 0, nil
	}
	if err := c.PushCompressed(ctx, compressed); err != nil {
		return 0, err
	}
	return series, nil
}

func (c *Client) PushCompressed(ctx context.Context, compressed []byte) error {
	if len(compressed) == 0 {
		return nil
	}
	if strings.TrimSpace(c.cfg.URL) == "" {
		return errors.New("remoteWrite.url is required")
	}

	attempts := 3
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			sleep := backoff(attempt)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(sleep):
			}
		}

		if err := c.pushOnce(ctx, compressed); err != nil {
			lastErr = err
			if !isRetryable(err) {
				return err
			}
			continue
		}
		return nil
	}

	if lastErr == nil {
		lastErr = errors.New("remote_write failed")
	}
	return lastErr
}

func (c *Client) pushOnce(ctx context.Context, compressed []byte) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("Content-Encoding", "snappy")
	httpReq.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	httpReq.Header.Set("User-Agent", c.cfg.UserAgent)
	if strings.TrimSpace(c.cfg.BearerToken) != "" {
		httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.cfg.BearerToken))
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return retryableError{err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 == 2 {
		io.Copy(io.Discard, resp.Body)
		return nil
	}

	// Read a small prefix for diagnostics.
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	err = fmt.Errorf("remote_write status=%d body=%q", resp.StatusCode, strings.TrimSpace(string(msg)))

	// Retry on overload / transient errors.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode/100 == 5 {
		return retryableError{err: err}
	}
	return err
}

type retryableError struct{ err error }

func (e retryableError) Error() string { return e.err.Error() }
func (e retryableError) Unwrap() error { return e.err }

func isRetryable(err error) bool {
	var re retryableError
	return errors.As(err, &re)
}

func backoff(attempt int) time.Duration {
	// 0: (unused), 1: ~250-350ms, 2: ~600-850ms
	base := 250 * time.Millisecond
	max := 5 * time.Second
	d := base * time.Duration(1<<uint(attempt-1))
	if d > max {
		d = max
	}
	// Add small jitter.
	j := time.Duration(rand.IntN(100)) * time.Millisecond
	return d + j
}
