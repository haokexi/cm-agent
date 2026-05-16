package hysteria

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
	defaultRepo = "apernet/hysteria"

	serviceName = "hysteria-server"
	installDir  = "/etc/hysteria"
	binaryPath  = "/usr/local/bin/hysteria"
	configPath  = "/etc/hysteria/config.yaml"
	metaPath    = "/etc/hysteria/client-meta.json"
	certPath    = "/etc/hysteria/cert.crt"
	keyPath     = "/etc/hysteria/private.key"
	versionFile = "/etc/hysteria/ver.txt"
	serviceFile = "/etc/systemd/system/hysteria-server.service"
)

type Config struct {
	Listen        string `json:"listen,omitempty"`
	Port          int    `json:"port,omitempty"`
	Password      string `json:"password,omitempty"`
	ObfsPassword  string `json:"obfsPassword,omitempty"`
	SNI           string `json:"sni,omitempty"`
	Insecure      bool   `json:"insecure"`
	CertPath      string `json:"certPath,omitempty"`
	KeyPath       string `json:"keyPath,omitempty"`
	MasqueradeURL string `json:"masqueradeUrl,omitempty"`
	UpMbps        int    `json:"upMbps,omitempty"`
	DownMbps      int    `json:"downMbps,omitempty"`
}

type Request struct {
	RequestID    string
	Action       string
	Version      string
	OpenFirewall bool
	Config       *Config
}

type Result struct {
	RequestID    string  `json:"request_id,omitempty"`
	Action       string  `json:"action,omitempty"`
	Success      bool    `json:"success"`
	Error        string  `json:"error,omitempty"`
	Message      string  `json:"message,omitempty"`
	Installed    bool    `json:"installed"`
	Running      bool    `json:"running"`
	Version      string  `json:"version,omitempty"`
	Config       *Config `json:"config,omitempty"`
	ServiceName  string  `json:"service_name,omitempty"`
	BinaryPath   string  `json:"binary_path,omitempty"`
	ConfigPath   string  `json:"config_path,omitempty"`
	StartedAtMs  int64   `json:"started_at_ms,omitempty"`
	FinishedAtMs int64   `json:"finished_at_ms,omitempty"`
}

type statusSnapshot struct {
	Installed bool
	Running   bool
	Version   string
	Config    *Config
}

type Manager struct {
	logger     *slog.Logger
	httpClient *http.Client
}

func NewManager(logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{logger: logger, httpClient: &http.Client{Timeout: 90 * time.Second}}
}

func (m *Manager) Execute(ctx context.Context, req Request) Result {
	startedAt := time.Now()
	res := Result{RequestID: strings.TrimSpace(req.RequestID), Action: strings.ToLower(strings.TrimSpace(req.Action)), ServiceName: serviceName, BinaryPath: binaryPath, ConfigPath: configPath, StartedAtMs: startedAt.UnixMilli()}
	defer func() { res.FinishedAtMs = time.Now().UnixMilli() }()
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
	res.Installed, res.Running, res.Version, res.Config = status.Installed, status.Running, status.Version, status.Config
	return res
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
	if err := ensureCertificate(ctx, &cfg); err != nil {
		return "", err
	}
	if err := writeConfig(cfg); err != nil {
		return "", err
	}
	if err := writeMeta(cfg); err != nil {
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
	message := "installed hysteria " + version
	if req.OpenFirewall {
		if note, err := openFirewallPort(ctx, cfg.Port); err != nil {
			message = joinMessages(message, "firewall warning: "+err.Error())
		} else {
			message = joinMessages(message, note)
		}
	}
	return message, nil
}

func (m *Manager) configure(ctx context.Context, req Request) (string, error) {
	if _, err := os.Stat(binaryPath); err != nil {
		return "", errors.New("hysteria is not installed")
	}
	cfg, err := normalizeConfig(req.Config, false)
	if err != nil {
		return "", err
	}
	if err := ensureCertificate(ctx, &cfg); err != nil {
		return "", err
	}
	if err := writeConfig(cfg); err != nil {
		return "", err
	}
	if err := writeMeta(cfg); err != nil {
		return "", err
	}
	if err := installServiceFile(); err != nil {
		return "", err
	}
	if err := runSystemctl(ctx, "daemon-reload"); err != nil {
		return "", err
	}
	if err := restartService(ctx); err != nil {
		return "", err
	}
	message := "configuration applied"
	if req.OpenFirewall {
		if note, err := openFirewallPort(ctx, cfg.Port); err != nil {
			message = joinMessages(message, "firewall warning: "+err.Error())
		} else {
			message = joinMessages(message, note)
		}
	}
	return message, nil
}

func (m *Manager) installBinary(ctx context.Context, version string) (string, error) {
	target := normalizeVersion(version)
	if target == "" || strings.EqualFold(target, "latest") {
		v, err := m.resolveLatestVersion(ctx)
		if err != nil {
			return "", err
		}
		target = v
	}
	if current := readVersion(); sameVersion(current, target) {
		if _, err := os.Stat(binaryPath); err == nil {
			return current, nil
		}
	}
	assetName, err := releaseAssetName()
	if err != nil {
		return "", err
	}
	tmpDir, err := os.MkdirTemp("", "hysteria-install-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	assetPath := filepath.Join(tmpDir, assetName)
	if err := m.downloadAsset(ctx, target, assetName, assetPath); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o755); err != nil {
		return "", fmt.Errorf("create binary dir: %w", err)
	}
	if err := copyFile(assetPath, binaryPath, 0o755); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(versionFile), 0o755); err != nil {
		return "", fmt.Errorf("create version dir: %w", err)
	}
	if err := os.WriteFile(versionFile, []byte(target+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write version file: %w", err)
	}
	return target, nil
}

func (m *Manager) resolveLatestVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://github.com/"+defaultRepo+"/releases/latest", nil)
	if err != nil {
		return "", fmt.Errorf("build latest request: %w", err)
	}
	req.Header.Set("User-Agent", "cm-agent-hysteria")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolve latest version: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	tag := strings.TrimSpace(resp.Request.URL.Path)
	if idx := strings.LastIndex(tag, "/tag/"); idx >= 0 {
		tag = tag[idx+5:]
	} else {
		tag = path.Base(tag)
	}
	tag, _ = url.PathUnescape(tag)
	tag = normalizeVersion(tag)
	if tag == "" || tag == "latest" {
		return "", errors.New("resolve latest version: invalid redirect path")
	}
	return tag, nil
}

func releaseAssetName() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "hysteria-linux-amd64", nil
	case "arm64":
		return "hysteria-linux-arm64", nil
	case "386":
		return "hysteria-linux-386", nil
	case "arm":
		return "hysteria-linux-arm", nil
	default:
		return "", fmt.Errorf("unsupported arch: %s", runtime.GOARCH)
	}
}

func (m *Manager) downloadAsset(ctx context.Context, version, assetName, outPath string) error {
	tag := "app/v" + strings.TrimPrefix(normalizeVersion(version), "v")
	rawURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", defaultRepo, url.PathEscape(tag), url.PathEscape(assetName))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}
	req.Header.Set("User-Agent", "cm-agent-hysteria")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download hysteria asset: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("download hysteria asset: status %d", resp.StatusCode)
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

func ensureCertificate(ctx context.Context, cfg *Config) error {
	if strings.TrimSpace(cfg.CertPath) != "" && strings.TrimSpace(cfg.KeyPath) != "" {
		return nil
	}
	cfg.CertPath, cfg.KeyPath = certPath, keyPath
	if _, certErr := os.Stat(certPath); certErr == nil {
		if _, keyErr := os.Stat(keyPath); keyErr == nil {
			return nil
		}
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		return errors.New("openssl is required to generate self-signed certificate")
	}
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return fmt.Errorf("create hysteria dir: %w", err)
	}
	cmd := exec.CommandContext(ctx, "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-subj", "/CN=www.bing.com", "-days", "36500")
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("generate self-signed certificate: %s", msg)
	}
	_ = os.Chmod(keyPath, 0o600)
	_ = os.Chmod(certPath, 0o644)
	return nil
}

func writeConfig(cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	lines := []string{"listen: " + yamlQuote(cfg.Listen), "", "tls:", "  cert: " + yamlQuote(cfg.CertPath), "  key: " + yamlQuote(cfg.KeyPath), "", "auth:", "  type: password", "  password: " + yamlQuote(cfg.Password)}
	if cfg.ObfsPassword != "" {
		lines = append(lines, "", "obfs:", "  type: salamander", "  salamander:", "    password: "+yamlQuote(cfg.ObfsPassword))
	}
	if cfg.MasqueradeURL != "" {
		lines = append(lines, "", "masquerade:", "  type: proxy", "  proxy:", "    url: "+yamlQuote(cfg.MasqueradeURL), "    rewriteHost: true")
	}
	if cfg.UpMbps > 0 || cfg.DownMbps > 0 {
		lines = append(lines, "", "bandwidth:")
		if cfg.UpMbps > 0 {
			lines = append(lines, fmt.Sprintf("  up: %d mbps", cfg.UpMbps))
		}
		if cfg.DownMbps > 0 {
			lines = append(lines, fmt.Sprintf("  down: %d mbps", cfg.DownMbps))
		}
	}
	payload := []byte(strings.Join(lines, "\n") + "\n")
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}
	return nil
}

func writeMeta(cfg Config) error {
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal client meta: %w", err)
	}
	payload = append(payload, '\n')
	return os.WriteFile(metaPath, payload, 0o600)
}

func readConfig() (*Config, error) {
	b, err := os.ReadFile(metaPath)
	if err == nil {
		var cfg Config
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, fmt.Errorf("parse client meta: %w", err)
		}
		cfg = applyConfigDefaults(cfg, true)
		return &cfg, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return nil, err
}

func installServiceFile() error {
	content := strings.Join([]string{
		"[Unit]",
		"Description=Hysteria Server Service",
		"After=network-online.target",
		"Wants=network-online.target",
		"",
		"[Service]",
		"Type=simple",
		"User=root",
		"ExecStart=" + binaryPath + " server -c " + configPath,
		"Restart=on-failure",
		"RestartSec=3s",
		"LimitNOFILE=1048576",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
		"",
	}, "\n")
	return os.WriteFile(serviceFile, []byte(content), 0o644)
}
func startService(ctx context.Context) error {
	if err := installServiceFile(); err != nil {
		return err
	}
	if err := runSystemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	return runSystemctl(ctx, "start", serviceName)
}
func stopService(ctx context.Context) error { return runSystemctl(ctx, "stop", serviceName) }
func restartService(ctx context.Context) error {
	if err := installServiceFile(); err != nil {
		return err
	}
	if err := runSystemctl(ctx, "daemon-reload"); err != nil {
		return err
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
	return "hysteria uninstalled", nil
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
			if err := runCmd(ctx, "ufw", "allow", fmt.Sprintf("%d/udp", port)); err != nil {
				return "", err
			}
			notes = append(notes, "ufw updated")
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		if err := runCmd(ctx, "firewall-cmd", "--permanent", "--add-port", fmt.Sprintf("%d/udp", port)); err == nil {
			if reloadErr := runCmd(ctx, "firewall-cmd", "--reload"); reloadErr == nil {
				notes = append(notes, "firewalld updated")
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
		if strings.TrimSpace(input.Listen) != "" {
			cfg.Listen = strings.TrimSpace(input.Listen)
		}
		if input.Port > 0 {
			cfg.Port = input.Port
		}
		if strings.TrimSpace(input.Password) != "" {
			cfg.Password = strings.TrimSpace(input.Password)
		}
		if strings.TrimSpace(input.ObfsPassword) != "" {
			cfg.ObfsPassword = strings.TrimSpace(input.ObfsPassword)
		}
		if strings.TrimSpace(input.SNI) != "" {
			cfg.SNI = strings.TrimSpace(input.SNI)
		}
		cfg.Insecure = input.Insecure
		if strings.TrimSpace(input.CertPath) != "" {
			cfg.CertPath = strings.TrimSpace(input.CertPath)
		}
		if strings.TrimSpace(input.KeyPath) != "" {
			cfg.KeyPath = strings.TrimSpace(input.KeyPath)
		}
		if strings.TrimSpace(input.MasqueradeURL) != "" {
			cfg.MasqueradeURL = strings.TrimSpace(input.MasqueradeURL)
		}
		if input.UpMbps > 0 {
			cfg.UpMbps = input.UpMbps
		}
		if input.DownMbps > 0 {
			cfg.DownMbps = input.DownMbps
		}
	}
	if cfg.Port <= 0 {
		if !allowGenerated {
			return Config{}, errors.New("port is required")
		}
		port, err := randomPort()
		if err != nil {
			return Config{}, err
		}
		cfg.Port = port
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return Config{}, errors.New("port must be in range 1-65535")
	}
	if cfg.Password == "" {
		if !allowGenerated {
			return Config{}, errors.New("password is required")
		}
		p, err := randomPassword()
		if err != nil {
			return Config{}, err
		}
		cfg.Password = p
	}
	if cfg.Listen == "" {
		cfg.Listen = ":" + fmt.Sprint(cfg.Port)
	} else if strings.HasPrefix(cfg.Listen, ":") || strings.Contains(cfg.Listen, ":") {
		if !strings.HasSuffix(cfg.Listen, fmt.Sprintf(":%d", cfg.Port)) {
			cfg.Listen = normalizeListen(cfg.Listen, cfg.Port)
		}
	} else {
		cfg.Listen = fmt.Sprintf("%s:%d", cfg.Listen, cfg.Port)
	}
	if cfg.CertPath == "" {
		cfg.CertPath = certPath
	}
	if cfg.KeyPath == "" {
		cfg.KeyPath = keyPath
	}
	if cfg.SNI == "" {
		cfg.SNI = "www.bing.com"
	}
	return cfg, nil
}
func applyConfigDefaults(cfg Config, preserveSecrets bool) Config {
	def := defaultConfig()
	if cfg.Listen == "" {
		cfg.Listen = def.Listen
	}
	if cfg.Port <= 0 {
		cfg.Port = portFromListen(cfg.Listen)
		if cfg.Port <= 0 {
			cfg.Port = def.Port
		}
	}
	if !preserveSecrets && cfg.Password == "" {
		cfg.Password = def.Password
	}
	if cfg.CertPath == "" {
		cfg.CertPath = certPath
	}
	if cfg.KeyPath == "" {
		cfg.KeyPath = keyPath
	}
	if cfg.SNI == "" {
		cfg.SNI = def.SNI
	}
	return cfg
}
func defaultConfig() Config {
	return Config{Listen: ":36712", Port: 36712, SNI: "www.bing.com", Insecure: true, CertPath: certPath, KeyPath: keyPath, MasqueradeURL: "https://www.bing.com"}
}
func normalizeListen(listen string, port int) string {
	listen = strings.TrimSpace(listen)
	if listen == "" || listen == ":" {
		return ":" + fmt.Sprint(port)
	}
	if strings.HasPrefix(listen, ":") {
		return ":" + fmt.Sprint(port)
	}
	if i := strings.LastIndex(listen, ":"); i > -1 {
		return listen[:i+1] + fmt.Sprint(port)
	}
	return fmt.Sprintf("%s:%d", listen, port)
}
func portFromListen(listen string) int {
	i := strings.LastIndex(strings.TrimSpace(listen), ":")
	if i < 0 {
		return 0
	}
	var p int
	_, _ = fmt.Sscanf(listen[i+1:], "%d", &p)
	return p
}
func randomPassword() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
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
	return os.Rename(tmp, dst)
}
func ensureSupportedHost() error {
	if runtime.GOOS != "linux" {
		return errors.New("hysteria management is only supported on linux")
	}
	if os.Geteuid() != 0 {
		return errors.New("hysteria management requires root privileges")
	}
	return nil
}
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "app/")
	v = strings.TrimPrefix(v, "app%2F")
	return strings.TrimPrefix(v, "v")
}
func sameVersion(a, b string) bool { return normalizeVersion(a) == normalizeVersion(b) }
func yamlQuote(s string) string    { b, _ := json.Marshal(s); return string(b) }
func joinMessages(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "; ")
}
