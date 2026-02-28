package selfupdate

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const defaultRepo = "haokexi/cm-agent"

var ErrAlreadyLatest = errors.New("already on target version")

type Config struct {
	Logger         *slog.Logger
	CurrentVersion string
	TargetVersion  string
	Repo           string
	GitHubProxy    string
	ExecPath       string
	HTTPClient     *http.Client
}

type Result struct {
	FromVersion string
	ToVersion   string
	AssetName   string
	AssetURL    string
}

func Apply(ctx context.Context, cfg Config) (Result, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 45 * time.Second}
	}

	repo := strings.TrimSpace(cfg.Repo)
	if repo == "" {
		repo = defaultRepo
	}

	exePath := strings.TrimSpace(cfg.ExecPath)
	if exePath == "" {
		p, err := os.Executable()
		if err != nil {
			return Result{}, fmt.Errorf("resolve executable: %w", err)
		}
		exePath = p
	}
	if p, err := filepath.EvalSymlinks(exePath); err == nil && strings.TrimSpace(p) != "" {
		exePath = p
	}

	assetName, binName, err := releaseNames(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return Result{}, err
	}

	target := strings.TrimSpace(cfg.TargetVersion)
	if target == "" || strings.EqualFold(target, "latest") {
		target, err = resolveLatestTag(ctx, cfg.HTTPClient, repo, cfg.GitHubProxy)
		if err != nil {
			return Result{}, err
		}
	}

	fromVersion := normalizeVersion(cfg.CurrentVersion)
	if sameVersion(fromVersion, target) {
		return Result{
			FromVersion: fromVersion,
			ToVersion:   target,
			AssetName:   assetName,
		}, ErrAlreadyLatest
	}

	tmpDir, err := os.MkdirTemp("", "cm-agent-selfupdate-*")
	if err != nil {
		return Result{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	assetFile := filepath.Join(tmpDir, assetName)
	assetURL, err := downloadReleaseAsset(ctx, cfg.HTTPClient, repo, target, assetName, cfg.GitHubProxy, assetFile)
	if err != nil {
		return Result{}, err
	}

	checksumFile := filepath.Join(tmpDir, assetName+".sha256")
	_, _ = downloadReleaseAsset(ctx, cfg.HTTPClient, repo, target, assetName+".sha256", cfg.GitHubProxy, checksumFile)
	if _, err := os.Stat(checksumFile); err == nil {
		if err := verifySHA256(assetFile, checksumFile); err != nil {
			return Result{}, err
		}
	}

	newBin := filepath.Join(tmpDir, "cm-agent.new")
	if err := extractBinary(assetFile, binName, newBin); err != nil {
		return Result{}, err
	}

	if err := os.Chmod(newBin, 0o755); err != nil {
		return Result{}, fmt.Errorf("chmod new binary: %w", err)
	}
	if err := replaceBinary(exePath, newBin); err != nil {
		return Result{}, err
	}

	cfg.Logger.Info("self update finished", "from", fromVersion, "to", target, "asset", assetName)
	return Result{
		FromVersion: fromVersion,
		ToVersion:   target,
		AssetName:   assetName,
		AssetURL:    assetURL,
	}, nil
}

func resolveLatestTag(ctx context.Context, client *http.Client, repo, ghProxy string) (string, error) {
	u := withProxy(ghProxy, "https://github.com/"+repo+"/releases/latest")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("build latest request: %w", err)
	}
	req.Header.Set("User-Agent", "cm-agent-updater")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolve latest tag: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	tag := path.Base(strings.TrimSpace(resp.Request.URL.Path))
	if tag == "" || tag == "latest" || tag == "releases" {
		return "", errors.New("resolve latest tag: invalid redirect path")
	}
	return tag, nil
}

func downloadReleaseAsset(
	ctx context.Context,
	client *http.Client,
	repo, target, asset, ghProxy, outPath string,
) (string, error) {
	var errs []string
	for _, t := range tagCandidates(target) {
		rawURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, url.PathEscape(t), url.PathEscape(asset))
		u := withProxy(ghProxy, rawURL)
		if err := downloadToFile(ctx, client, u, outPath); err == nil {
			return u, nil
		} else {
			errs = append(errs, fmt.Sprintf("%s (%v)", u, err))
		}
	}
	return "", fmt.Errorf("download release asset failed: %s", strings.Join(errs, "; "))
}

func downloadToFile(ctx context.Context, client *http.Client, u, outPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "cm-agent-updater")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Sync()
}

func verifySHA256(assetPath, checksumPath string) error {
	expected, err := readChecksum(checksumPath)
	if err != nil {
		return err
	}
	f, err := os.Open(assetPath)
	if err != nil {
		return fmt.Errorf("open asset for checksum: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash asset: %w", err)
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("sha256 mismatch: expected=%s actual=%s", expected, actual)
	}
	return nil
}

func readChecksum(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read checksum file: %w", err)
	}
	fields := strings.Fields(string(b))
	for _, f := range fields {
		v := strings.TrimSpace(f)
		if len(v) != 64 {
			continue
		}
		if _, err := hex.DecodeString(v); err == nil {
			return strings.ToLower(v), nil
		}
	}
	return "", errors.New("checksum file missing valid sha256")
}

func extractBinary(archivePath, binName, outPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open release archive: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar stream: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if path.Base(hdr.Name) != binName {
			continue
		}
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return fmt.Errorf("create extracted binary: %w", err)
		}
		_, cErr := io.Copy(out, tr)
		sErr := out.Sync()
		clErr := out.Close()
		if cErr != nil {
			return fmt.Errorf("write extracted binary: %w", cErr)
		}
		if sErr != nil {
			return fmt.Errorf("sync extracted binary: %w", sErr)
		}
		if clErr != nil {
			return fmt.Errorf("close extracted binary: %w", clErr)
		}
		return nil
	}
	return fmt.Errorf("binary %q not found in archive", binName)
}

func replaceBinary(exePath, newBinPath string) error {
	dstDir := filepath.Dir(exePath)
	stagePath := filepath.Join(dstDir, "."+filepath.Base(exePath)+".new")
	if err := os.Remove(stagePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cleanup previous stage file: %w", err)
	}
	if err := copyFile(newBinPath, stagePath, 0o755); err != nil {
		return fmt.Errorf("stage binary: %w", err)
	}
	if err := os.Rename(stagePath, exePath); err != nil {
		return fmt.Errorf("replace executable: %w", err)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, cErr := io.Copy(out, in)
	sErr := out.Sync()
	clErr := out.Close()
	if cErr != nil {
		return cErr
	}
	if sErr != nil {
		return sErr
	}
	return clErr
}

func releaseNames(goos, goarch string) (asset string, bin string, err error) {
	switch goos {
	case "linux":
		switch goarch {
		case "amd64":
			return "cm-agent-linux-amd64.tgz", "cm-agent-linux-amd64", nil
		case "arm64":
			return "cm-agent-linux-arm64.tgz", "cm-agent-linux-arm64", nil
		default:
			return "", "", fmt.Errorf("unsupported architecture for self update: %s", goarch)
		}
	default:
		return "", "", fmt.Errorf("unsupported os for self update: %s", goos)
	}
}

func withProxy(proxy, rawURL string) string {
	p := strings.TrimSpace(proxy)
	if p == "" {
		return rawURL
	}
	return strings.TrimRight(p, "/") + "/" + rawURL
}

func tagCandidates(tag string) []string {
	t := strings.TrimSpace(tag)
	if t == "" {
		return nil
	}
	out := []string{t}
	if strings.HasPrefix(t, "v") {
		out = append(out, strings.TrimPrefix(t, "v"))
	} else {
		out = append(out, "v"+t)
	}
	uniq := make([]string, 0, len(out))
	seen := make(map[string]struct{}, len(out))
	for _, v := range out {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		uniq = append(uniq, v)
	}
	return uniq
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	return v
}

func sameVersion(a, b string) bool {
	na := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(a)), "v")
	nb := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(b)), "v")
	return na != "" && na == nb
}
