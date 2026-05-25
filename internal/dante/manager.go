package dante

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	serviceName = "danted"
	installDir  = "/etc/danted"
	configPath  = "/etc/danted.conf"
	metaPath    = "/etc/danted/client-meta.json"
	binaryPath  = "/usr/sbin/sockd"
)

type Config struct {
	Listen      string `json:"listen,omitempty"`
	Port        int    `json:"port,omitempty"`
	External    string `json:"external,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	AllowNoAuth bool   `json:"allowNoAuth"`
}

type Request struct {
	RequestID    string
	Action       string
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

type Manager struct{ logger *slog.Logger }

func NewManager(logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{logger: logger}
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
	if err := installPackage(ctx); err != nil {
		return "", err
	}
	if err := applySystemUser(ctx, cfg); err != nil {
		return "", err
	}
	if err := writeConfig(cfg); err != nil {
		return "", err
	}
	if err := writeMeta(cfg); err != nil {
		return "", err
	}
	if err := runSystemctl(ctx, "enable", serviceName); err != nil {
		return "", err
	}
	if err := restartService(ctx); err != nil {
		return "", err
	}
	msg := "installed dante socks5"
	if req.OpenFirewall {
		if note, err := openFirewallPort(ctx, cfg.Port); err != nil {
			msg = joinMessages(msg, "firewall warning: "+err.Error())
		} else {
			msg = joinMessages(msg, note)
		}
	}
	return msg, nil
}

func (m *Manager) configure(ctx context.Context, req Request) (string, error) {
	if !isInstalled() {
		return "", errors.New("dante is not installed")
	}
	cfg, err := normalizeConfig(req.Config, false)
	if err != nil {
		return "", err
	}
	if err := applySystemUser(ctx, cfg); err != nil {
		return "", err
	}
	if err := writeConfig(cfg); err != nil {
		return "", err
	}
	if err := writeMeta(cfg); err != nil {
		return "", err
	}
	if err := restartService(ctx); err != nil {
		return "", err
	}
	msg := "configuration applied"
	if req.OpenFirewall {
		if note, err := openFirewallPort(ctx, cfg.Port); err != nil {
			msg = joinMessages(msg, "firewall warning: "+err.Error())
		} else {
			msg = joinMessages(msg, note)
		}
	}
	return msg, nil
}

func installPackage(ctx context.Context) error {
	if isInstalled() {
		return nil
	}
	if _, err := exec.LookPath("apt-get"); err == nil {
		return installPackageApt(ctx)
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		if err := runCmd(ctx, "dnf", "install", "-y", "dante-server"); err != nil {
			return fmt.Errorf("install dante-server failed; on RHEL/CentOS enable EPEL first: %w", err)
		}
		return nil
	}
	if _, err := exec.LookPath("yum"); err == nil {
		if err := runCmd(ctx, "yum", "install", "-y", "dante-server"); err != nil {
			return fmt.Errorf("install dante-server failed; on RHEL/CentOS enable EPEL first: %w", err)
		}
		return nil
	}
	return errors.New("no supported package manager found (apt-get/dnf/yum)")
}

func installPackageApt(ctx context.Context) error {
	_ = runCmd(ctx, "apt-get", "update")
	if err := runCmd(ctx, "apt-get", "install", "-y", "dante-server"); err == nil {
		return nil
	} else {
		firstErr := err
		// Ubuntu keeps dante-server in the universe repository; minimal images often do not enable it.
		if isUbuntuHost() {
			if _, lookErr := exec.LookPath("add-apt-repository"); lookErr != nil {
				_ = runCmd(ctx, "apt-get", "install", "-y", "software-properties-common")
			}
			if _, lookErr := exec.LookPath("add-apt-repository"); lookErr == nil {
				_ = runCmd(ctx, "add-apt-repository", "-y", "universe")
				_ = runCmd(ctx, "apt-get", "update")
				if retryErr := runCmd(ctx, "apt-get", "install", "-y", "dante-server"); retryErr == nil {
					return nil
				}
			}
		}
		// Some distributions expose the daemon under a different package name.
		if altErr := runCmd(ctx, "apt-get", "install", "-y", "sockd"); altErr == nil {
			return nil
		}
		return fmt.Errorf("install dante-server failed; on Ubuntu enable universe first: sudo add-apt-repository universe && sudo apt-get update: %w", firstErr)
	}
}

func isUbuntuHost() bool {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}
	s := strings.ToLower(string(b))
	return strings.Contains(s, "id=ubuntu") || strings.Contains(s, "id_like=ubuntu")
}

func applySystemUser(ctx context.Context, cfg Config) error {
	if cfg.AllowNoAuth || cfg.Username == "" {
		return nil
	}
	if err := runCmd(ctx, "id", "-u", cfg.Username); err != nil {
		shell := "/usr/sbin/nologin"
		if _, statErr := os.Stat(shell); statErr != nil {
			shell = "/sbin/nologin"
		}
		if err := runCmd(ctx, "useradd", "-r", "-M", "-s", shell, cfg.Username); err != nil {
			return err
		}
	}
	cmd := exec.CommandContext(ctx, "chpasswd")
	cmd.Stdin = strings.NewReader(cfg.Username + ":" + cfg.Password + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("chpasswd: %s", msg)
	}
	return nil
}

func writeConfig(cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	socksmethod := "username"
	if cfg.AllowNoAuth || cfg.Username == "" {
		socksmethod = "none"
	}
	lines := []string{
		"logoutput: syslog",
		"internal: " + cfg.Listen + " port = " + strconv.Itoa(cfg.Port),
		"external: " + cfg.External,
		"clientmethod: none",
		"socksmethod: " + socksmethod,
		"user.privileged: root",
		"user.unprivileged: nobody",
		"",
		"client pass {",
		"  from: 0.0.0.0/0 to: 0.0.0.0/0",
		"  log: connect disconnect error",
		"}",
		"",
		"socks pass {",
		"  from: 0.0.0.0/0 to: 0.0.0.0/0",
		"  command: bind connect udpassociate",
		"  protocol: tcp udp",
		"  log: connect disconnect error",
		"}",
	}
	return os.WriteFile(configPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

func writeMeta(cfg Config) error {
	if err := os.MkdirAll(installDir, 0o700); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metaPath, append(payload, '\n'), 0o600)
}

func readConfig() (*Config, error) {
	b, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	cfg = applyConfigDefaults(cfg, true)
	return &cfg, nil
}

func collectStatus(ctx context.Context) (statusSnapshot, error) {
	out := statusSnapshot{Installed: isInstalled(), Version: readVersion(ctx)}
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

func isInstalled() bool { _, err := os.Stat(binaryPath); return err == nil }

func readVersion(ctx context.Context) string {
	if !isInstalled() {
		return ""
	}
	cmd := exec.CommandContext(ctx, binaryPath, "-v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	text := strings.TrimSpace(string(out))
	if idx := strings.IndexByte(text, '\n'); idx >= 0 {
		text = text[:idx]
	}
	return text
}

func startService(ctx context.Context) error { return runSystemctl(ctx, "start", serviceName) }
func stopService(ctx context.Context) error  { return runSystemctl(ctx, "stop", serviceName) }
func restartService(ctx context.Context) error {
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
	_ = os.Remove(configPath)
	if err := os.RemoveAll(installDir); err != nil {
		return "", err
	}
	return "dante configuration removed; package is left installed", nil
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
		if strings.TrimSpace(input.External) != "" {
			cfg.External = strings.TrimSpace(input.External)
		}
		if strings.TrimSpace(input.Username) != "" {
			cfg.Username = strings.TrimSpace(input.Username)
		}
		if strings.TrimSpace(input.Password) != "" {
			cfg.Password = strings.TrimSpace(input.Password)
		}
		cfg.AllowNoAuth = input.AllowNoAuth
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return Config{}, errors.New("port must be in range 1-65535")
	}
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0"
	}
	if cfg.External == "" {
		cfg.External = defaultExternalInterface()
	}
	if cfg.External == "" {
		return Config{}, errors.New("external interface is required")
	}
	if !cfg.AllowNoAuth {
		if cfg.Username == "" {
			cfg.Username = "socksuser"
		}
		if !validUsername(cfg.Username) {
			return Config{}, errors.New("username must match [a-z_][a-z0-9_-]{0,31}")
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
	}
	return cfg, nil
}

func applyConfigDefaults(cfg Config, preserveSecrets bool) Config {
	def := defaultConfig()
	if cfg.Listen == "" {
		cfg.Listen = def.Listen
	}
	if cfg.Port <= 0 {
		cfg.Port = def.Port
	}
	if cfg.External == "" {
		cfg.External = defaultExternalInterface()
	}
	if cfg.Username == "" && !cfg.AllowNoAuth {
		cfg.Username = def.Username
	}
	if cfg.Password == "" && !preserveSecrets && !cfg.AllowNoAuth {
		cfg.Password = def.Password
	}
	return cfg
}

func defaultConfig() Config {
	return Config{Listen: "0.0.0.0", Port: 1080, External: defaultExternalInterface(), Username: "socksuser", Password: "", AllowNoAuth: false}
}

func defaultExternalInterface() string {
	cmd := exec.Command("ip", "route", "show", "default")
	out, err := cmd.Output()
	if err != nil {
		return "eth0"
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return "eth0"
}

func validUsername(v string) bool {
	if len(v) < 1 || len(v) > 32 {
		return false
	}
	for i, r := range v {
		if i == 0 {
			if !(r == '_' || (r >= 'a' && r <= 'z')) {
				return false
			}
			continue
		}
		if !(r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func randomPassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func openFirewallPort(ctx context.Context, port int) (string, error) {
	var notes []string
	if _, err := exec.LookPath("ufw"); err == nil {
		cmd := exec.CommandContext(ctx, "ufw", "status")
		if out, statusErr := cmd.CombinedOutput(); statusErr == nil && strings.Contains(string(out), "Status: active") {
			if err := runCmd(ctx, "ufw", "allow", fmt.Sprintf("%d/tcp", port)); err != nil {
				return "", err
			}
			notes = append(notes, "ufw updated")
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		if err := runCmd(ctx, "firewall-cmd", "--permanent", "--add-port", fmt.Sprintf("%d/tcp", port)); err == nil {
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

func runSystemctl(ctx context.Context, args ...string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl is required")
	}
	return runCmd(ctx, "systemctl", args...)
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
func ensureSupportedHost() error {
	if runtime.GOOS != "linux" {
		return errors.New("dante management is only supported on linux")
	}
	if os.Geteuid() != 0 {
		return errors.New("dante management requires root privileges")
	}
	return nil
}
func joinMessages(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "; ")
}
