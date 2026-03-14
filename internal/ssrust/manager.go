package ssrust

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	defaultRepo = "shadowsocks/shadowsocks-rust"

	serviceName = "ss-rust"
	installDir  = "/etc/ss-rust"
	binaryPath  = "/usr/local/bin/ss-rust"
	configPath  = "/etc/ss-rust/config.json"
	versionFile = "/etc/ss-rust/ver.txt"
	serviceFile = "/etc/systemd/system/ss-rust.service"
)

type Config struct {
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	Password   string `json:"password,omitempty"`
	Method     string `json:"method,omitempty"`
	Mode       string `json:"mode,omitempty"`
	FastOpen   bool   `json:"fast_open"`
	Timeout    int    `json:"timeout,omitempty"`
	NameServer string `json:"nameserver,omitempty"`
	Plugin     string `json:"plugin,omitempty"`
	PluginOpts string `json:"plugin_opts,omitempty"`
	User       string `json:"user,omitempty"`
}

type Request struct {
	RequestID    string
	Action       string
	Version      string
	OpenFirewall bool
	Config       *Config
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
	return res
}

type statusSnapshot struct {
	Installed bool
	Running   bool
	Version   string
	Config    *Config
}

func (m *Manager) install(ctx context.Context, req Request) (string, error) {
	cfg, err := normalizeConfig(req.Config, true)
	if err != nil {
		return "", err
	}
	version, err := m.installBinary(ctx, strings.TrimSpace(req.Version))
	if err != nil {
		return "", err
	}
	if err := writeConfig(cfg); err != nil {
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

	message := "installed shadowsocks-rust " + version
	if req.OpenFirewall {
		if note, err := openFirewallPort(ctx, cfg.ServerPort); err != nil {
			message = joinMessages(message, "firewall warning: "+err.Error())
		} else {
			message = joinMessages(message, note)
		}
	}
	return message, nil
}

func (m *Manager) configure(ctx context.Context, req Request) (string, error) {
	if _, err := os.Stat(binaryPath); err != nil {
		return "", errors.New("shadowsocks-rust is not installed")
	}
	cfg, err := normalizeConfig(req.Config, false)
	if err != nil {
		return "", err
	}
	if err := writeConfig(cfg); err != nil {
		return "", err
	}
	if err := restartService(ctx); err != nil {
		return "", err
	}
	message := "configuration applied"
	if req.OpenFirewall {
		if note, err := openFirewallPort(ctx, cfg.ServerPort); err != nil {
			message = joinMessages(message, "firewall warning: "+err.Error())
		} else {
			message = joinMessages(message, note)
		}
	}
	return message, nil
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

	tmpDir, err := os.MkdirTemp("", "ssrust-install-*")
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
	req.Header.Set("User-Agent", "cm-agent-ssrust")
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
		return "shadowsocks-vVERSION.x86_64-unknown-linux-gnu.tar.xz", nil
	case "arm64":
		return "shadowsocks-vVERSION.aarch64-unknown-linux-gnu.tar.xz", nil
	case "386":
		return "shadowsocks-vVERSION.i686-unknown-linux-musl.tar.xz", nil
	default:
		return "", fmt.Errorf("unsupported arch: %s", runtime.GOARCH)
	}
}

func (m *Manager) downloadAsset(ctx context.Context, version, assetName, outPath string) error {
	assetName = strings.ReplaceAll(assetName, "VERSION", version)
	rawURL := fmt.Sprintf("https://github.com/%s/releases/download/v%s/%s", defaultRepo, url.PathEscape(version), url.PathEscape(assetName))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}
	req.Header.Set("User-Agent", "cm-agent-ssrust")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download ss-rust asset: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("download ss-rust asset: status %d", resp.StatusCode)
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
	cmd := exec.CommandContext(ctx, "tar", "-xJf", archivePath, "-C", outDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("extract ss-rust archive: %s", msg)
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
		if path.Base(p) == "ssserver" {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("scan extracted archive: %w", err)
	}
	if strings.TrimSpace(found) == "" {
		return "", errors.New("ssserver binary not found in release archive")
	}
	return found, nil
}

func writeConfig(cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}
	return nil
}

func installServiceFile() error {
	content := strings.Join([]string{
		"[Unit]",
		"Description=Shadowsocks Rust Service",
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
	if err := runSystemctl(ctx, "start", serviceName); err != nil {
		return err
	}
	return nil
}

func stopService(ctx context.Context) error {
	if err := runSystemctl(ctx, "stop", serviceName); err != nil {
		return err
	}
	return nil
}

func restartService(ctx context.Context) error {
	if err := runSystemctl(ctx, "restart", serviceName); err != nil {
		return err
	}
	return nil
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
	return "shadowsocks-rust uninstalled", nil
}

func collectStatus(ctx context.Context) (statusSnapshot, error) {
	out := statusSnapshot{}
	if _, err := os.Stat(binaryPath); err == nil {
		out.Installed = true
	}
	out.Version = readVersion()
	cfg, err := readConfig()
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

func readConfig() (*Config, error) {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	cfg = applyConfigDefaults(cfg, false)
	return &cfg, nil
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

func openFirewallPort(ctx context.Context, port int) (string, error) {
	var notes []string
	if _, err := exec.LookPath("ufw"); err == nil {
		cmd := exec.CommandContext(ctx, "ufw", "status")
		if out, statusErr := cmd.CombinedOutput(); statusErr == nil && strings.Contains(string(out), "Status: active") {
			if err := runCmd(ctx, "ufw", "allow", fmt.Sprintf("%d/tcp", port)); err != nil {
				return "", err
			}
			if err := runCmd(ctx, "ufw", "allow", fmt.Sprintf("%d/udp", port)); err != nil {
				return "", err
			}
			notes = append(notes, "ufw updated")
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		if err := runCmd(ctx, "firewall-cmd", "--permanent", "--add-port", fmt.Sprintf("%d/tcp", port)); err == nil {
			if err := runCmd(ctx, "firewall-cmd", "--permanent", "--add-port", fmt.Sprintf("%d/udp", port)); err == nil {
				if reloadErr := runCmd(ctx, "firewall-cmd", "--reload"); reloadErr == nil {
					notes = append(notes, "firewalld updated")
				}
			}
		}
	}
	if len(notes) == 0 {
		return "no managed firewall detected", nil
	}
	return strings.Join(notes, ", "), nil
}

func runCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return nil
}

func normalizeConfig(input *Config, allowGenerated bool) (Config, error) {
	cfg := defaultConfig()
	if input != nil {
		if strings.TrimSpace(input.Server) != "" {
			cfg.Server = strings.TrimSpace(input.Server)
		}
		if input.ServerPort > 0 {
			cfg.ServerPort = input.ServerPort
		}
		if strings.TrimSpace(input.Password) != "" {
			cfg.Password = strings.TrimSpace(input.Password)
		}
		if strings.TrimSpace(input.Method) != "" {
			cfg.Method = strings.TrimSpace(input.Method)
		}
		if strings.TrimSpace(input.Mode) != "" {
			cfg.Mode = strings.TrimSpace(input.Mode)
		}
		cfg.FastOpen = input.FastOpen
		if input.Timeout > 0 {
			cfg.Timeout = input.Timeout
		}
		cfg.NameServer = strings.TrimSpace(input.NameServer)
		cfg.Plugin = strings.TrimSpace(input.Plugin)
		cfg.PluginOpts = strings.TrimSpace(input.PluginOpts)
		if strings.TrimSpace(input.User) != "" {
			cfg.User = strings.TrimSpace(input.User)
		}
	}
	if cfg.ServerPort <= 0 {
		if !allowGenerated {
			return Config{}, errors.New("server_port is required")
		}
		port, err := randomPort()
		if err != nil {
			return Config{}, err
		}
		cfg.ServerPort = port
	}
	if cfg.ServerPort < 1 || cfg.ServerPort > 65535 {
		return Config{}, errors.New("server_port must be in range 1-65535")
	}
	if cfg.Password == "" {
		if !allowGenerated {
			return Config{}, errors.New("password is required")
		}
		password, err := randomPassword()
		if err != nil {
			return Config{}, err
		}
		cfg.Password = password
	}
	if cfg.Method == "" {
		return Config{}, errors.New("method is required")
	}
	if cfg.Mode == "" {
		cfg.Mode = "tcp_and_udp"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 300
	}
	if cfg.Server == "" {
		cfg.Server = "::"
	}
	if cfg.User == "" {
		cfg.User = "nobody"
	}
	return cfg, nil
}

func applyConfigDefaults(cfg Config, preserveSecrets bool) Config {
	def := defaultConfig()
	if strings.TrimSpace(cfg.Server) == "" {
		cfg.Server = def.Server
	}
	if cfg.ServerPort <= 0 {
		cfg.ServerPort = def.ServerPort
	}
	if !preserveSecrets && strings.TrimSpace(cfg.Password) == "" {
		cfg.Password = def.Password
	}
	if strings.TrimSpace(cfg.Method) == "" {
		cfg.Method = def.Method
	}
	if strings.TrimSpace(cfg.Mode) == "" {
		cfg.Mode = def.Mode
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = def.Timeout
	}
	if strings.TrimSpace(cfg.User) == "" {
		cfg.User = def.User
	}
	return cfg
}

func defaultConfig() Config {
	return Config{
		Server:     "::",
		ServerPort: 8388,
		Method:     "aes-256-gcm",
		Mode:       "tcp_and_udp",
		FastOpen:   false,
		Timeout:    300,
		User:       "nobody",
	}
}

func randomPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func randomPort() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(50000))
	if err != nil {
		return 0, fmt.Errorf("generate random port: %w", err)
	}
	return 10000 + int(n.Int64()), nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source binary: %w", err)
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create target binary: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return fmt.Errorf("flush binary: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close binary: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}
	return nil
}

func ensureSupportedHost() error {
	if runtime.GOOS != "linux" {
		return errors.New("shadowsocks-rust management is only supported on linux")
	}
	if os.Geteuid() != 0 {
		return errors.New("shadowsocks-rust management requires root privileges")
	}
	return nil
}

func sameVersion(a, b string) bool {
	return strings.TrimPrefix(strings.TrimSpace(a), "v") == strings.TrimPrefix(strings.TrimSpace(b), "v")
}

func joinMessages(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, "; ")
}
