package realm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRepo = "zhboner/realm"

	serviceName = "realm"
	installDir  = "/etc/realm"
	binaryPath  = "/usr/local/bin/realm"
	configPath  = "/etc/realm/config.toml"
	versionFile = "/etc/realm/ver.txt"
	serviceFile = "/etc/systemd/system/realm.service"
)

type NetworkConfig struct {
	NoTCP    bool `json:"no_tcp,omitempty"`
	UseUDP   bool `json:"use_udp,omitempty"`
	IPv6Only bool `json:"ipv6_only,omitempty"`
}

type Endpoint struct {
	Remark string `json:"remark,omitempty"`
	Listen string `json:"listen,omitempty"`
	Remote string `json:"remote,omitempty"`
}

type Config struct {
	Network   NetworkConfig `json:"network,omitempty"`
	Endpoints []Endpoint    `json:"endpoints,omitempty"`
}

type Request struct {
	RequestID string
	Action    string
	Version   string
	Config    *Config
}

type Result struct {
	RequestID string `json:"request_id,omitempty"`
	Action    string `json:"action,omitempty"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	Message   string `json:"message,omitempty"`

	Installed bool    `json:"installed"`
	Running   bool    `json:"running"`
	Version   string  `json:"version,omitempty"`
	Config    *Config `json:"config,omitempty"`

	ServiceName string `json:"service_name,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	ConfigPath  string `json:"config_path,omitempty"`

	StartedAtMs  int64 `json:"started_at_ms,omitempty"`
	FinishedAtMs int64 `json:"finished_at_ms,omitempty"`
}

type statusSnapshot struct {
	Installed  bool
	Running    bool
	Version    string
	Config     *Config
	BinaryPath string
	ConfigPath string
	UnitPath   string
}

type runtimePaths struct {
	BinaryPath string
	ConfigPath string
	UnitPath   string
}

type Manager struct {
	logger     *slog.Logger
	httpClient *http.Client
}

func NewManager(logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		logger: logger,
		httpClient: &http.Client{
			Timeout: 90 * time.Second,
		},
	}
}

func (m *Manager) Execute(ctx context.Context, req Request) Result {
	startedAt := time.Now()
	res := Result{
		RequestID:   strings.TrimSpace(req.RequestID),
		Action:      strings.ToLower(strings.TrimSpace(req.Action)),
		ServiceName: serviceName,
		BinaryPath:  binaryPath,
		ConfigPath:  configPath,
		StartedAtMs: startedAt.UnixMilli(),
	}
	defer func() {
		res.FinishedAtMs = time.Now().UnixMilli()
	}()

	if err := ensureSupportedHost(); err != nil {
		res.Error = err.Error()
		return res
	}

	switch res.Action {
	case "install":
		msg, err := m.install(ctx, req)
		res.Message = msg
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Success = true
		}
	case "configure":
		msg, err := m.configure(ctx, req)
		res.Message = msg
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Success = true
		}
	case "start":
		if err := startService(ctx); err != nil {
			res.Error = err.Error()
		} else {
			res.Success = true
			res.Message = "service started"
		}
	case "stop":
		if err := stopService(ctx); err != nil {
			res.Error = err.Error()
		} else {
			res.Success = true
			res.Message = "service stopped"
		}
	case "restart":
		if err := restartService(ctx); err != nil {
			res.Error = err.Error()
		} else {
			res.Success = true
			res.Message = "service restarted"
		}
	case "status":
		res.Success = true
	case "uninstall":
		msg, err := uninstall(ctx)
		res.Message = msg
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Success = true
		}
	default:
		res.Error = "unsupported action"
	}

	status, err := collectStatus(ctx)
	if err != nil {
		if res.Error == "" {
			res.Error = err.Error()
		} else {
			res.Message = joinMessages(res.Message, "status warning: "+err.Error())
		}
		return res
	}
	res.Installed = status.Installed
	res.Running = status.Running
	res.Version = status.Version
	res.Config = status.Config
	if strings.TrimSpace(status.BinaryPath) != "" {
		res.BinaryPath = status.BinaryPath
	}
	if strings.TrimSpace(status.ConfigPath) != "" {
		res.ConfigPath = status.ConfigPath
	}
	return res
}

func (m *Manager) install(ctx context.Context, req Request) (string, error) {
	cfg, err := normalizeConfig(req.Config)
	if err != nil {
		return "", err
	}
	version, err := m.installBinary(ctx, strings.TrimSpace(req.Version))
	if err != nil {
		return "", err
	}
	if err := writeConfig(configPath, cfg); err != nil {
		return "", err
	}
	if err := installServiceFile(); err != nil {
		return "", err
	}
	if err := runSystemctl(ctx, "daemon-reload"); err != nil {
		return "", err
	}
	if err := runSystemctl(ctx, "enable", serviceName); err != nil {
		return "", err
	}
	if err := runSystemctl(ctx, "restart", serviceName); err != nil {
		if err := runSystemctl(ctx, "start", serviceName); err != nil {
			return "", err
		}
	}
	return "installed realm " + version, nil
}

func (m *Manager) configure(ctx context.Context, req Request) (string, error) {
	paths, _ := discoverRuntimePaths(ctx)
	targetBinaryPath := firstExistingOrDefault([]string{paths.BinaryPath, binaryPath, legacyBinaryPath()})
	if targetBinaryPath == "" {
		return "", errors.New("realm is not installed")
	}
	cfg, err := normalizeConfig(req.Config)
	if err != nil {
		return "", err
	}
	targetConfigPath := firstNonEmpty(paths.ConfigPath, configPath)
	if err := writeConfig(targetConfigPath, cfg); err != nil {
		return "", err
	}
	if err := runSystemctl(ctx, "restart", serviceName); err != nil {
		if err := runSystemctl(ctx, "start", serviceName); err != nil {
			return "", err
		}
	}
	return "configuration applied", nil
}

func (m *Manager) installBinary(ctx context.Context, version string) (string, error) {
	targetVersion := strings.TrimSpace(version)
	if targetVersion == "" || strings.EqualFold(targetVersion, "latest") {
		var err error
		targetVersion, err = m.resolveLatestVersion(ctx)
		if err != nil {
			return "", err
		}
	}
	targetVersion = strings.TrimPrefix(targetVersion, "v")

	if current := readVersion(); sameVersion(current, targetVersion) {
		if _, err := os.Stat(binaryPath); err == nil {
			return current, nil
		}
	}

	assetName, err := releaseAssetName()
	if err != nil {
		return "", err
	}

	tmpDir, err := os.MkdirTemp("", "realm-install-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	assetPath := filepath.Join(tmpDir, assetName)
	if err := m.downloadAsset(ctx, targetVersion, assetName, assetPath); err != nil {
		return "", err
	}
	if err := extractArchive(ctx, assetPath, tmpDir); err != nil {
		return "", err
	}
	sourcePath, err := findExtractedBinary(tmpDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o755); err != nil {
		return "", fmt.Errorf("create binary dir: %w", err)
	}
	if err := copyFile(sourcePath, binaryPath, 0o755); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(versionFile), 0o755); err != nil {
		return "", fmt.Errorf("create version dir: %w", err)
	}
	if err := os.WriteFile(versionFile, []byte(targetVersion+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write version file: %w", err)
	}
	return targetVersion, nil
}

func (m *Manager) resolveLatestVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://github.com/"+defaultRepo+"/releases/latest", nil)
	if err != nil {
		return "", fmt.Errorf("build latest request: %w", err)
	}
	req.Header.Set("User-Agent", "cm-agent-realm")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolve latest version: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	tag := path.Base(strings.TrimSpace(resp.Request.URL.Path))
	tag = strings.TrimPrefix(tag, "v")
	if tag == "" || tag == "latest" {
		return "", errors.New("resolve latest version: invalid redirect path")
	}
	return tag, nil
}

func releaseAssetName() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "realm-x86_64-unknown-linux-gnu.tar.gz", nil
	case "arm64":
		return "realm-aarch64-unknown-linux-gnu.tar.gz", nil
	default:
		return "", fmt.Errorf("unsupported arch: %s", runtime.GOARCH)
	}
}

func (m *Manager) downloadAsset(ctx context.Context, version, assetName, outPath string) error {
	rawURL := fmt.Sprintf("https://github.com/%s/releases/download/v%s/%s", defaultRepo, url.PathEscape(version), url.PathEscape(assetName))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}
	req.Header.Set("User-Agent", "cm-agent-realm")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download realm asset: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("download realm asset: status %d", resp.StatusCode)
	}

	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create asset file: %w", err)
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write asset file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("flush asset file: %w", err)
	}
	return nil
}

func extractArchive(ctx context.Context, archivePath, outDir string) error {
	cmd := exec.CommandContext(ctx, "tar", "-xzf", archivePath, "-C", outDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("extract realm archive: %s", msg)
	}
	return nil
}

func findExtractedBinary(root string) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if path.Base(p) == "realm" {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("scan extracted archive: %w", err)
	}
	if strings.TrimSpace(found) == "" {
		return "", errors.New("realm binary not found in release archive")
	}
	return found, nil
}

func renderConfig(cfg Config) ([]byte, error) {
	cfg, err := normalizeConfig(&cfg)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	if len(cfg.Endpoints) == 0 {
		b.WriteString("endpoints = []\n\n")
	}
	b.WriteString("[network]\n")
	fmt.Fprintf(&b, "no_tcp = %t\n", cfg.Network.NoTCP)
	fmt.Fprintf(&b, "use_udp = %t\n", cfg.Network.UseUDP)
	fmt.Fprintf(&b, "ipv6_only = %t\n", cfg.Network.IPv6Only)
	for _, ep := range cfg.Endpoints {
		b.WriteString("\n")
		if strings.TrimSpace(ep.Remark) != "" {
			fmt.Fprintf(&b, "# 备注: %s\n", sanitizeComment(ep.Remark))
		}
		b.WriteString("[[endpoints]]\n")
		fmt.Fprintf(&b, "listen = %q\n", ep.Listen)
		fmt.Fprintf(&b, "remote = %q\n", ep.Remote)
	}
	return []byte(b.String()), nil
}

func installServiceFile() error {
	content := strings.Join([]string{
		"[Unit]",
		"Description=Realm Proxy Service",
		"After=network-online.target",
		"Wants=network-online.target",
		"",
		"[Service]",
		"Type=simple",
		"User=root",
		"ExecStart=" + binaryPath + " -c " + configPath,
		"Restart=on-failure",
		"RestartSec=3s",
		"LimitNOFILE=1048576",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
		"",
	}, "\n")
	if err := os.WriteFile(serviceFile, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}
	return nil
}

func startService(ctx context.Context) error {
	paths, _ := discoverRuntimePaths(ctx)
	targetBinaryPath := firstExistingOrDefault([]string{paths.BinaryPath, binaryPath, legacyBinaryPath()})
	if targetBinaryPath == "" {
		return errors.New("realm is not installed")
	}
	return runSystemctl(ctx, "start", serviceName)
}

func stopService(ctx context.Context) error {
	return runSystemctl(ctx, "stop", serviceName)
}

func restartService(ctx context.Context) error {
	paths, _ := discoverRuntimePaths(ctx)
	targetBinaryPath := firstExistingOrDefault([]string{paths.BinaryPath, binaryPath, legacyBinaryPath()})
	if targetBinaryPath == "" {
		return errors.New("realm is not installed")
	}
	return runSystemctl(ctx, "restart", serviceName)
}

func uninstall(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = runSystemctl(ctx, "stop", serviceName)
		_ = runSystemctl(ctx, "disable", serviceName)
	}
	_ = os.Remove(serviceFile)
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = runSystemctl(ctx, "daemon-reload")
	}
	_ = os.Remove(binaryPath)
	if err := os.RemoveAll(installDir); err != nil {
		return "", fmt.Errorf("remove install dir: %w", err)
	}
	return "realm uninstalled", nil
}

func collectStatus(ctx context.Context) (statusSnapshot, error) {
	out := statusSnapshot{}
	paths, _ := discoverRuntimePaths(ctx)
	out.BinaryPath = firstExistingOrDefault([]string{paths.BinaryPath, binaryPath, legacyBinaryPath()})
	out.ConfigPath = firstReadableOrDefault([]string{paths.ConfigPath, configPath, legacyConfigPath()})
	out.UnitPath = firstExistingOrDefault([]string{paths.UnitPath, serviceFile})
	out.Installed = out.BinaryPath != "" || out.ConfigPath != "" || out.UnitPath != ""
	out.Version = readVersion()
	cfg, err := readConfig(out.ConfigPath)
	if err == nil {
		out.Config = cfg
	} else if out.Installed && !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		cmd := exec.CommandContext(ctx, "systemctl", "is-active", serviceName)
		if output, runErr := cmd.CombinedOutput(); runErr == nil {
			out.Running = strings.TrimSpace(string(output)) == "active"
		}
	}
	return out, nil
}

func readConfig(targetPath string) (*Config, error) {
	if strings.TrimSpace(targetPath) == "" {
		return nil, os.ErrNotExist
	}
	b, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, err
	}
	cfg, err := parseConfigBytes(b)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func parseConfigBytes(b []byte) (Config, error) {
	cfg := defaultConfig()
	var currentEndpoint *Endpoint
	var pendingRemark string

	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	section := ""
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			remark := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if strings.HasPrefix(remark, "备注:") {
				pendingRemark = strings.TrimSpace(strings.TrimPrefix(remark, "备注:"))
			} else if strings.HasPrefix(strings.ToLower(remark), "remark:") {
				pendingRemark = strings.TrimSpace(remark[7:])
			}
			continue
		}
		switch line {
		case "[network]":
			if currentEndpoint != nil {
				cfg.Endpoints = appendEndpoint(cfg.Endpoints, *currentEndpoint)
				currentEndpoint = nil
			}
			section = "network"
			continue
		case "[[endpoints]]":
			if currentEndpoint != nil {
				cfg.Endpoints = appendEndpoint(cfg.Endpoints, *currentEndpoint)
			}
			currentEndpoint = &Endpoint{Remark: pendingRemark}
			pendingRemark = ""
			section = "endpoint"
			continue
		}

		key, value, ok := splitKV(line)
		if !ok {
			continue
		}
		switch section {
		case "network":
			bv, err := parseBoolValue(value)
			if err != nil {
				return Config{}, fmt.Errorf("parse network config line %d: %w", lineNo, err)
			}
			switch key {
			case "no_tcp":
				cfg.Network.NoTCP = bv
			case "use_udp":
				cfg.Network.UseUDP = bv
			case "ipv6_only":
				cfg.Network.IPv6Only = bv
			}
		case "endpoint":
			if currentEndpoint == nil {
				currentEndpoint = &Endpoint{Remark: pendingRemark}
				pendingRemark = ""
			}
			sv, err := parseStringValue(value)
			if err != nil {
				return Config{}, fmt.Errorf("parse endpoint line %d: %w", lineNo, err)
			}
			switch key {
			case "listen":
				currentEndpoint.Listen = sv
			case "remote":
				currentEndpoint.Remote = sv
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, fmt.Errorf("scan config file: %w", err)
	}
	if currentEndpoint != nil {
		cfg.Endpoints = appendEndpoint(cfg.Endpoints, *currentEndpoint)
	}
	return normalizeConfig(&cfg)
}

func splitKV(line string) (string, string, bool) {
	idx := strings.Index(line, "=")
	if idx <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	value := strings.TrimSpace(line[idx+1:])
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

func parseBoolValue(v string) (bool, error) {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return false, fmt.Errorf("invalid bool %q", v)
	}
	return b, nil
}

func parseStringValue(v string) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", fmt.Errorf("invalid string %q", v)
	}
	out, err := strconv.Unquote(v)
	if err != nil {
		return "", fmt.Errorf("unquote string %q: %w", v, err)
	}
	return out, nil
}

func appendEndpoint(list []Endpoint, ep Endpoint) []Endpoint {
	if strings.TrimSpace(ep.Listen) == "" && strings.TrimSpace(ep.Remote) == "" {
		return list
	}
	return append(list, ep)
}

func readVersion() string {
	b, err := os.ReadFile(versionFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func runSystemctl(ctx context.Context, args ...string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl is required")
	}
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), msg)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source file: %w", err)
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("open target file: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy file contents: %w", err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("flush target file: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close target file: %w", err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod target file: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace target file: %w", err)
	}
	return nil
}

func ensureSupportedHost() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("unsupported os: %s", runtime.GOOS)
	}
	return nil
}

func sameVersion(a, b string) bool {
	return strings.TrimSpace(strings.TrimPrefix(a, "v")) == strings.TrimSpace(strings.TrimPrefix(b, "v"))
}

func joinMessages(parts ...string) string {
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, "; ")
}

func sanitizeComment(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func legacyBinaryPath() string {
	return "/root/realm/realm"
}

func legacyConfigPath() string {
	return "/root/realm/config.toml"
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstExistingOrDefault(values []string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, err := os.Stat(v); err == nil {
			return v
		}
	}
	return ""
}

func firstReadableOrDefault(values []string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, err := os.Stat(v); err == nil {
			return v
		}
	}
	return ""
}

func writeConfig(targetPath string, cfg Config) error {
	payload, err := renderConfig(cfg)
	if err != nil {
		return err
	}
	if strings.TrimSpace(targetPath) == "" {
		return errors.New("config path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(targetPath, payload, 0o600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}
	return nil
}

func discoverRuntimePaths(ctx context.Context) (runtimePaths, error) {
	var out runtimePaths

	if pid, err := readMainPID(ctx); err == nil && pid > 1 {
		if args, err := readProcArgs(pid); err == nil {
			bin, cfg := extractPathsFromArgs(args)
			out.BinaryPath = firstNonEmpty(out.BinaryPath, bin)
			out.ConfigPath = firstNonEmpty(out.ConfigPath, cfg)
		}
	}

	unitPath, err := readUnitPath(ctx)
	if err == nil {
		out.UnitPath = unitPath
	}
	if strings.TrimSpace(out.UnitPath) != "" {
		if args, err := parseExecStartFromUnitFile(out.UnitPath); err == nil {
			bin, cfg := extractPathsFromArgs(args)
			out.BinaryPath = firstNonEmpty(out.BinaryPath, bin)
			out.ConfigPath = firstNonEmpty(out.ConfigPath, cfg)
		}
	}

	return out, nil
}

func readMainPID(ctx context.Context) (int, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return 0, err
	}
	cmd := exec.CommandContext(ctx, "systemctl", "show", serviceName, "--property", "MainPID", "--value")
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return 0, fmt.Errorf("read main pid: %s", msg)
	}
	pidText := strings.TrimSpace(string(output))
	if pidText == "" {
		return 0, nil
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil {
		return 0, fmt.Errorf("parse main pid %q: %w", pidText, err)
	}
	return pid, nil
}

func readUnitPath(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		if _, statErr := os.Stat(serviceFile); statErr == nil {
			return serviceFile, nil
		}
		return "", err
	}
	cmd := exec.CommandContext(ctx, "systemctl", "show", serviceName, "--property", "FragmentPath", "--value")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if _, statErr := os.Stat(serviceFile); statErr == nil {
			return serviceFile, nil
		}
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("read unit path: %s", msg)
	}
	pathText := strings.TrimSpace(string(output))
	if pathText == "" || pathText == "[not set]" {
		if _, statErr := os.Stat(serviceFile); statErr == nil {
			return serviceFile, nil
		}
		return "", os.ErrNotExist
	}
	return pathText, nil
}

func readProcArgs(pid int) ([]string, error) {
	if pid <= 1 {
		return nil, errors.New("invalid pid")
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, err
	}
	var args []string
	for _, part := range strings.Split(string(data), "\x00") {
		part = strings.TrimSpace(part)
		if part != "" {
			args = append(args, part)
		}
	}
	if len(args) == 0 {
		return nil, errors.New("empty cmdline")
	}
	return args, nil
}

func parseExecStartFromUnitFile(unitPath string) ([]string, error) {
	data, err := os.ReadFile(unitPath)
	if err != nil {
		return nil, err
	}
	var logicalLines []string
	var current strings.Builder
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.HasSuffix(line, "\\") {
			current.WriteString(strings.TrimSuffix(line, "\\"))
			continue
		}
		current.WriteString(line)
		logicalLines = append(logicalLines, current.String())
		current.Reset()
	}
	if current.Len() > 0 {
		logicalLines = append(logicalLines, current.String())
	}

	for _, line := range logicalLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "ExecStart="))
		value = strings.TrimLeft(value, "-+!:@")
		return splitCommandLine(value)
	}
	return nil, os.ErrNotExist
}

func splitCommandLine(command string) ([]string, error) {
	var (
		args     []string
		current  strings.Builder
		inSingle bool
		inDouble bool
		escaped  bool
	)

	flush := func() {
		if current.Len() > 0 {
			args = append(args, current.String())
			current.Reset()
		}
	}

	for _, r := range command {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
		case r == '"' && !inSingle:
			inDouble = !inDouble
		case (r == ' ' || r == '\t') && !inSingle && !inDouble:
			flush()
		default:
			current.WriteRune(r)
		}
	}
	if escaped || inSingle || inDouble {
		return nil, fmt.Errorf("invalid command line %q", command)
	}
	flush()
	if len(args) == 0 {
		return nil, os.ErrNotExist
	}
	return args, nil
}

func extractPathsFromArgs(args []string) (string, string) {
	if len(args) == 0 {
		return "", ""
	}
	binPath := strings.TrimSpace(args[0])
	var configFile string
	for i := 1; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		switch {
		case arg == "-c" || arg == "--config":
			if i+1 < len(args) {
				configFile = strings.TrimSpace(args[i+1])
			}
		case strings.HasPrefix(arg, "-c="):
			configFile = strings.TrimSpace(strings.TrimPrefix(arg, "-c="))
		case strings.HasPrefix(arg, "--config="):
			configFile = strings.TrimSpace(strings.TrimPrefix(arg, "--config="))
		}
		if configFile != "" {
			break
		}
	}
	return binPath, configFile
}

func defaultConfig() Config {
	return Config{
		Network: NetworkConfig{
			NoTCP:    false,
			UseUDP:   true,
			IPv6Only: false,
		},
		Endpoints: []Endpoint{},
	}
}

func normalizeConfig(input *Config) (Config, error) {
	cfg := defaultConfig()
	if input != nil {
		cfg.Network.NoTCP = input.Network.NoTCP
		cfg.Network.UseUDP = input.Network.UseUDP
		cfg.Network.IPv6Only = input.Network.IPv6Only
		cfg.Endpoints = cfg.Endpoints[:0]
		for _, raw := range input.Endpoints {
			ep := Endpoint{
				Remark: sanitizeComment(raw.Remark),
				Listen: strings.TrimSpace(raw.Listen),
				Remote: strings.TrimSpace(raw.Remote),
			}
			if ep.Listen == "" && ep.Remote == "" {
				continue
			}
			if ep.Listen == "" || ep.Remote == "" {
				return Config{}, errors.New("endpoint listen/remote are required")
			}
			if err := validateAddress(ep.Listen); err != nil {
				return Config{}, fmt.Errorf("invalid listen address %q: %w", ep.Listen, err)
			}
			if err := validateAddress(ep.Remote); err != nil {
				return Config{}, fmt.Errorf("invalid remote address %q: %w", ep.Remote, err)
			}
			cfg.Endpoints = append(cfg.Endpoints, ep)
		}
	}
	return cfg, nil
}

func validateAddress(addr string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return err
	}
	if strings.TrimSpace(host) == "" {
		return errors.New("host is required")
	}
	p, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil {
		return err
	}
	if p < 1 || p > 65535 {
		return fmt.Errorf("port out of range: %d", p)
	}
	return nil
}
