package xray

import (
	"archive/zip"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
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
	defaultRepo = "XTLS/Xray-core"

	serviceName    = "xray"
	installDir     = "/etc/xray"
	binaryPath     = "/usr/local/bin/xray"
	configPath     = "/etc/xray/config.json"
	clientMetaPath = "/etc/xray/client-meta.json"
	versionFile    = "/etc/xray/ver.txt"
	serviceFile    = "/etc/systemd/system/xray.service"
)

type Config struct {
	Listen      string   `json:"listen,omitempty"`
	Port        int      `json:"port,omitempty"`
	UUID        string   `json:"uuid,omitempty"`
	Flow        string   `json:"flow,omitempty"`
	Dest        string   `json:"dest,omitempty"`
	ServerNames []string `json:"serverNames,omitempty"`
	PrivateKey  string   `json:"privateKey,omitempty"`
	PublicKey   string   `json:"publicKey,omitempty"`
	ShortIds    []string `json:"shortIds,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	SpiderX     string   `json:"spiderX,omitempty"`
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

	ConfigValid      *bool  `json:"config_valid,omitempty"`
	ValidateMessage  string `json:"validate_message,omitempty"`
	ListenReachable  *bool  `json:"listen_reachable,omitempty"`
	ListenTestTarget string `json:"listen_test_target,omitempty"`
	ListenError      string `json:"listen_error,omitempty"`

	ServiceName string `json:"service_name,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	ConfigPath  string `json:"config_path,omitempty"`

	StartedAtMs  int64 `json:"started_at_ms,omitempty"`
	FinishedAtMs int64 `json:"finished_at_ms,omitempty"`
}

type checkOutcome struct {
	Config           *Config
	ConfigValid      *bool
	ValidateMessage  string
	ListenReachable  *bool
	ListenTestTarget string
	ListenError      string
	Message          string
}

type statusSnapshot struct {
	Installed bool
	Running   bool
	Version   string
	Config    *Config
}

type clientMeta struct {
	Fingerprint string `json:"fingerprint,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

type runtimeConfigFile struct {
	Log       runtimeLog        `json:"log,omitempty"`
	Inbounds  []runtimeInbound  `json:"inbounds,omitempty"`
	Outbounds []runtimeOutbound `json:"outbounds,omitempty"`
}

type runtimeLog struct {
	LogLevel string `json:"loglevel,omitempty"`
}

type runtimeInbound struct {
	Listen         string                 `json:"listen,omitempty"`
	Port           int                    `json:"port,omitempty"`
	Protocol       string                 `json:"protocol,omitempty"`
	Settings       runtimeInboundSettings `json:"settings,omitempty"`
	StreamSettings runtimeStreamSettings  `json:"streamSettings,omitempty"`
}

type runtimeInboundSettings struct {
	Clients    []runtimeClient `json:"clients,omitempty"`
	Decryption string          `json:"decryption,omitempty"`
}

type runtimeClient struct {
	ID   string `json:"id,omitempty"`
	Flow string `json:"flow,omitempty"`
}

type runtimeStreamSettings struct {
	Network         string          `json:"network,omitempty"`
	Security        string          `json:"security,omitempty"`
	RealitySettings realitySettings `json:"realitySettings,omitempty"`
}

type realitySettings struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest,omitempty"`
	Xver        int      `json:"xver,omitempty"`
	ServerNames []string `json:"serverNames,omitempty"`
	PrivateKey  string   `json:"privateKey,omitempty"`
	ShortIds    []string `json:"shortIds,omitempty"`
}

type runtimeOutbound struct {
	Protocol string `json:"protocol,omitempty"`
	Tag      string `json:"tag,omitempty"`
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
	case "validate":
		outcome, err := m.validate(ctx, req)
		res.Config = outcome.Config
		res.ConfigValid = outcome.ConfigValid
		res.ValidateMessage = outcome.ValidateMessage
		res.ListenReachable = outcome.ListenReachable
		res.ListenTestTarget = outcome.ListenTestTarget
		res.ListenError = outcome.ListenError
		res.Message = outcome.Message
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Success = true
		}
	case "self_check":
		outcome, err := m.selfCheck(ctx)
		res.Config = outcome.Config
		res.ConfigValid = outcome.ConfigValid
		res.ValidateMessage = outcome.ValidateMessage
		res.ListenReachable = outcome.ListenReachable
		res.ListenTestTarget = outcome.ListenTestTarget
		res.ListenError = outcome.ListenError
		res.Message = outcome.Message
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
	if res.Config == nil {
		res.Config = status.Config
	}
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
	validateMessage, err := m.validateRuntimeConfig(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("xray config validation failed before install: %w", err)
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

	listenTarget, listenErr := selfCheckListen(ctx, cfg, 6, time.Second)
	if listenErr != nil {
		return "", fmt.Errorf("xray listen self-check failed after install: %w", listenErr)
	}

	message := joinMessages(
		"installed xray "+version,
		validateMessage,
		"listen reachable via "+listenTarget,
	)
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
		return "", errors.New("xray is not installed")
	}
	cfg, err := normalizeConfig(req.Config, false)
	if err != nil {
		return "", err
	}
	validateMessage, err := m.validateRuntimeConfig(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("xray config validation failed before apply: %w", err)
	}
	if err := writeConfig(cfg); err != nil {
		return "", err
	}
	if err := restartService(ctx); err != nil {
		if err := startService(ctx); err != nil {
			return "", err
		}
	}
	listenTarget, listenErr := selfCheckListen(ctx, cfg, 6, time.Second)
	if listenErr != nil {
		return "", fmt.Errorf("xray listen self-check failed after apply: %w", listenErr)
	}
	message := joinMessages(
		"configuration applied",
		validateMessage,
		"listen reachable via "+listenTarget,
	)
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

	tmpDir, err := os.MkdirTemp("", "xray-install-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	assetPath := filepath.Join(tmpDir, assetName)
	if err := m.downloadAsset(ctx, targetVersion, assetName, assetPath); err != nil {
		return "", err
	}
	if err := extractArchive(assetPath, tmpDir); err != nil {
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
	req.Header.Set("User-Agent", "cm-agent-xray")
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
		return "Xray-linux-64.zip", nil
	case "arm64":
		return "Xray-linux-arm64-v8a.zip", nil
	case "386":
		return "Xray-linux-32.zip", nil
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
	req.Header.Set("User-Agent", "cm-agent-xray")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download xray asset: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("download xray asset: status %d", resp.StatusCode)
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

func extractArchive(archivePath, outDir string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open xray archive: %w", err)
	}
	defer zr.Close()

	root := filepath.Clean(outDir)
	prefix := root + string(os.PathSeparator)
	for _, file := range zr.File {
		target := filepath.Clean(filepath.Join(root, file.Name))
		if target != root && !strings.HasPrefix(target, prefix) {
			return fmt.Errorf("illegal zip path: %s", file.Name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("create dir: %w", err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("create parent dir: %w", err)
		}
		rc, err := file.Open()
		if err != nil {
			return fmt.Errorf("open archived file: %w", err)
		}
		mode := file.Mode()
		if mode == 0 {
			mode = 0o644
		}
		if path.Base(file.Name) == "xray" {
			mode = 0o755
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			rc.Close()
			return fmt.Errorf("create extracted file: %w", err)
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			return fmt.Errorf("extract file: %w", err)
		}
		if err := out.Close(); err != nil {
			rc.Close()
			return fmt.Errorf("close extracted file: %w", err)
		}
		if err := rc.Close(); err != nil {
			return fmt.Errorf("close archive entry: %w", err)
		}
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
		if path.Base(p) == "xray" {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("scan extracted archive: %w", err)
	}
	if strings.TrimSpace(found) == "" {
		return "", errors.New("xray binary not found in release archive")
	}
	return found, nil
}

func writeConfig(cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	runtimeCfg := buildRuntimeConfig(cfg)
	payload, err := json.MarshalIndent(runtimeCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	metaPayload, err := json.MarshalIndent(clientMeta{Fingerprint: cfg.Fingerprint, SpiderX: cfg.SpiderX}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal client meta: %w", err)
	}
	metaPayload = append(metaPayload, '\n')
	if err := os.WriteFile(clientMetaPath, metaPayload, 0o600); err != nil {
		return fmt.Errorf("write client meta: %w", err)
	}
	return nil
}

func buildRuntimeConfig(cfg Config) runtimeConfigFile {
	return runtimeConfigFile{
		Log: runtimeLog{LogLevel: "warning"},
		Inbounds: []runtimeInbound{{
			Listen:   cfg.Listen,
			Port:     cfg.Port,
			Protocol: "vless",
			Settings: runtimeInboundSettings{
				Clients: []runtimeClient{{
					ID:   cfg.UUID,
					Flow: cfg.Flow,
				}},
				Decryption: "none",
			},
			StreamSettings: runtimeStreamSettings{
				Network:  "tcp",
				Security: "reality",
				RealitySettings: realitySettings{
					Show:        false,
					Dest:        cfg.Dest,
					Xver:        0,
					ServerNames: cfg.ServerNames,
					PrivateKey:  cfg.PrivateKey,
					ShortIds:    cfg.ShortIds,
				},
			},
		}},
		Outbounds: []runtimeOutbound{
			{Protocol: "freedom", Tag: "direct"},
			{Protocol: "blackhole", Tag: "block"},
		},
	}
}

func installServiceFile() error {
	content := strings.Join([]string{
		"[Unit]",
		"Description=Xray Service",
		"After=network-online.target",
		"Wants=network-online.target",
		"",
		"[Service]",
		"Type=simple",
		"User=root",
		"ExecStart=" + binaryPath + " run -config " + configPath,
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
	return runSystemctl(ctx, "start", serviceName)
}

func stopService(ctx context.Context) error {
	return runSystemctl(ctx, "stop", serviceName)
}

func restartService(ctx context.Context) error {
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
	_ = os.Remove(clientMetaPath)
	if err := os.RemoveAll(installDir); err != nil {
		return "", fmt.Errorf("remove install dir: %w", err)
	}
	return "xray uninstalled", nil
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
	payload, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var runtimeCfg runtimeConfigFile
	if err := json.Unmarshal(payload, &runtimeCfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	if len(runtimeCfg.Inbounds) == 0 {
		return nil, errors.New("xray config has no inbounds")
	}
	inbound := runtimeCfg.Inbounds[0]
	if len(inbound.Settings.Clients) == 0 {
		return nil, errors.New("xray config has no clients")
	}
	client := inbound.Settings.Clients[0]
	cfg := Config{
		Listen:      inbound.Listen,
		Port:        inbound.Port,
		UUID:        client.ID,
		Flow:        client.Flow,
		Dest:        inbound.StreamSettings.RealitySettings.Dest,
		ServerNames: normalizeStringList(inbound.StreamSettings.RealitySettings.ServerNames),
		PrivateKey:  strings.TrimSpace(inbound.StreamSettings.RealitySettings.PrivateKey),
		ShortIds:    normalizeStringList(inbound.StreamSettings.RealitySettings.ShortIds),
	}
	if meta, err := readClientMeta(); err == nil {
		cfg.Fingerprint = meta.Fingerprint
		cfg.SpiderX = meta.SpiderX
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if cfg.PrivateKey != "" {
		publicKey, err := publicKeyFromPrivate(cfg.PrivateKey)
		if err != nil {
			return nil, err
		}
		cfg.PublicKey = publicKey
	}
	cfg = applyConfigDefaults(cfg)
	return &cfg, nil
}

func readClientMeta() (clientMeta, error) {
	payload, err := os.ReadFile(clientMetaPath)
	if err != nil {
		return clientMeta{}, err
	}
	var meta clientMeta
	if err := json.Unmarshal(payload, &meta); err != nil {
		return clientMeta{}, fmt.Errorf("parse client meta: %w", err)
	}
	return meta, nil
}

func readVersion() string {
	payload, err := os.ReadFile(versionFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(payload))
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

func (m *Manager) validate(ctx context.Context, req Request) (checkOutcome, error) {
	if req.Config == nil {
		return checkOutcome{}, errors.New("xray config is required")
	}
	cfg, err := normalizeConfig(req.Config, false)
	if err != nil {
		return checkOutcome{}, err
	}
	outcome := checkOutcome{Config: &cfg}
	msg, err := m.validateRuntimeConfig(ctx, cfg)
	outcome.ConfigValid = boolPtr(err == nil)
	outcome.ValidateMessage = msg
	if err != nil {
		outcome.Message = "configuration validation failed"
		return outcome, err
	}
	outcome.Message = "configuration is valid"
	return outcome, nil
}

func (m *Manager) selfCheck(ctx context.Context) (checkOutcome, error) {
	cfg, err := readConfig()
	if err != nil {
		return checkOutcome{}, err
	}
	outcome := checkOutcome{Config: cfg}
	validateMsg, validateErr := m.validateConfigFile(ctx, configPath)
	outcome.ConfigValid = boolPtr(validateErr == nil)
	outcome.ValidateMessage = validateMsg

	listenTarget, listenErr := selfCheckListen(ctx, *cfg, 2, 500*time.Millisecond)
	outcome.ListenReachable = boolPtr(listenErr == nil)
	outcome.ListenTestTarget = listenTarget
	if listenErr != nil {
		outcome.ListenError = listenErr.Error()
	}
	outcome.Message = describeSelfCheck(validateErr == nil, listenErr == nil)

	var errs []string
	if validateErr != nil {
		errs = append(errs, "config validation failed: "+validateErr.Error())
	}
	if listenErr != nil {
		errs = append(errs, "listen self-check failed: "+listenErr.Error())
	}
	if len(errs) > 0 {
		return outcome, errors.New(strings.Join(errs, "; "))
	}
	return outcome, nil
}

func (m *Manager) validateRuntimeConfig(ctx context.Context, cfg Config) (string, error) {
	tmpFile, err := os.CreateTemp("", "xray-config-*.json")
	if err != nil {
		return "", fmt.Errorf("create temp config: %w", err)
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)

	payload, err := json.MarshalIndent(buildRuntimeConfig(cfg), "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal temp config: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(tmpPath, payload, 0o600); err != nil {
		return "", fmt.Errorf("write temp config: %w", err)
	}
	return m.validateConfigFile(ctx, tmpPath)
}

func (m *Manager) validateConfigFile(ctx context.Context, filePath string) (string, error) {
	if _, err := os.Stat(binaryPath); err != nil {
		return "", errors.New("xray is not installed")
	}
	cmd := exec.CommandContext(ctx, binaryPath, "run", "-test", "-config", filePath)
	output, err := cmd.CombinedOutput()
	msg := strings.TrimSpace(string(output))
	if err != nil {
		if msg == "" {
			msg = err.Error()
		}
		return msg, fmt.Errorf("xray run -test failed: %s", msg)
	}
	if msg == "" {
		msg = "xray run -test passed"
	}
	return msg, nil
}

func selfCheckListen(ctx context.Context, cfg Config, attempts int, interval time.Duration) (string, error) {
	candidates, err := buildListenCandidates(cfg.Listen, cfg.Port)
	if err != nil {
		return "", err
	}
	if attempts < 1 {
		attempts = 1
	}
	var errs []string
	for attempt := 0; attempt < attempts; attempt++ {
		errThisRound := errs[:0]
		for _, candidate := range candidates {
			if err := testTCPDial(ctx, candidate); err == nil {
				return candidate, nil
			} else {
				errThisRound = append(errThisRound, fmt.Sprintf("%s (%s)", candidate, err.Error()))
			}
		}
		errs = append([]string(nil), errThisRound...)
		if attempt+1 < attempts && interval > 0 {
			if err := sleepWithContext(ctx, interval); err != nil {
				break
			}
		}
	}
	return firstNonEmpty(candidates...), errors.New(strings.Join(errs, "; "))
}

func buildListenCandidates(listen string, port int) ([]string, error) {
	host := strings.TrimSpace(listen)
	if host == "" {
		return nil, errors.New("listen is required")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	joined := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	parsedHost, parsedPort, err := net.SplitHostPort(joined)
	if err != nil {
		return nil, err
	}
	switch parsedHost {
	case "0.0.0.0":
		return []string{net.JoinHostPort("127.0.0.1", parsedPort)}, nil
	case "::":
		return []string{
			net.JoinHostPort("::1", parsedPort),
			net.JoinHostPort("127.0.0.1", parsedPort),
		}, nil
	default:
		return []string{net.JoinHostPort(parsedHost, parsedPort)}, nil
	}
}

func testTCPDial(ctx context.Context, address string) error {
	timeout := 3 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", strings.TrimSpace(address))
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func sleepWithContext(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func describeSelfCheck(configValid, listenReachable bool) string {
	switch {
	case configValid && listenReachable:
		return "config is valid and listen is reachable"
	case configValid && !listenReachable:
		return "config is valid but listen is unreachable"
	case !configValid && listenReachable:
		return "config is invalid but listen is reachable"
	default:
		return "config is invalid and listen is unreachable"
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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
		if strings.TrimSpace(input.UUID) != "" {
			cfg.UUID = strings.TrimSpace(input.UUID)
		}
		if strings.TrimSpace(input.Flow) != "" {
			cfg.Flow = strings.TrimSpace(input.Flow)
		}
		if strings.TrimSpace(input.Dest) != "" {
			cfg.Dest = strings.TrimSpace(input.Dest)
		}
		if names := normalizeStringList(input.ServerNames); len(names) > 0 {
			cfg.ServerNames = names
		}
		if strings.TrimSpace(input.PrivateKey) != "" {
			cfg.PrivateKey = strings.TrimSpace(input.PrivateKey)
		}
		if ids := normalizeStringList(input.ShortIds); len(ids) > 0 {
			cfg.ShortIds = ids
		}
		if strings.TrimSpace(input.Fingerprint) != "" {
			cfg.Fingerprint = strings.TrimSpace(input.Fingerprint)
		}
		if input.SpiderX != "" {
			cfg.SpiderX = input.SpiderX
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
	if cfg.UUID == "" {
		if !allowGenerated {
			return Config{}, errors.New("uuid is required")
		}
		uuid, err := generateUUID()
		if err != nil {
			return Config{}, err
		}
		cfg.UUID = uuid
	}
	if cfg.Dest == "" {
		return Config{}, errors.New("dest is required")
	}
	if _, _, err := splitHostPort(cfg.Dest); err != nil {
		return Config{}, err
	}
	if len(cfg.ServerNames) == 0 {
		host, _, err := splitHostPort(cfg.Dest)
		if err != nil {
			return Config{}, err
		}
		cfg.ServerNames = []string{host}
	}
	if cfg.PrivateKey == "" {
		if !allowGenerated {
			return Config{}, errors.New("privateKey is required")
		}
		privateKey, publicKey, err := generateRealityKeyPair()
		if err != nil {
			return Config{}, err
		}
		cfg.PrivateKey = privateKey
		cfg.PublicKey = publicKey
	} else {
		publicKey, err := publicKeyFromPrivate(cfg.PrivateKey)
		if err != nil {
			return Config{}, err
		}
		cfg.PublicKey = publicKey
	}
	if len(cfg.ShortIds) == 0 {
		if !allowGenerated {
			return Config{}, errors.New("shortIds is required")
		}
		shortID, err := generateShortID()
		if err != nil {
			return Config{}, err
		}
		cfg.ShortIds = []string{shortID}
	}
	for _, shortID := range cfg.ShortIds {
		if err := validateShortID(shortID); err != nil {
			return Config{}, err
		}
	}
	cfg = applyConfigDefaults(cfg)
	return cfg, nil
}

func applyConfigDefaults(cfg Config) Config {
	def := defaultConfig()
	if strings.TrimSpace(cfg.Listen) == "" {
		cfg.Listen = def.Listen
	}
	if cfg.Port <= 0 {
		cfg.Port = def.Port
	}
	if strings.TrimSpace(cfg.Flow) == "" {
		cfg.Flow = def.Flow
	}
	if len(cfg.ServerNames) == 0 {
		cfg.ServerNames = append([]string(nil), def.ServerNames...)
	}
	if len(cfg.ShortIds) == 0 {
		cfg.ShortIds = append([]string(nil), def.ShortIds...)
	}
	if strings.TrimSpace(cfg.Fingerprint) == "" {
		cfg.Fingerprint = def.Fingerprint
	}
	cfg.ServerNames = normalizeStringList(cfg.ServerNames)
	cfg.ShortIds = normalizeStringList(cfg.ShortIds)
	return cfg
}

func defaultConfig() Config {
	return Config{
		Listen:      "0.0.0.0",
		Port:        443,
		Flow:        "xtls-rprx-vision",
		Dest:        "www.yahoo.com:443",
		ServerNames: []string{"www.yahoo.com"},
		Fingerprint: "chrome",
	}
}

func normalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func splitHostPort(value string) (string, string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return "", "", errors.New("dest must be in host:port format")
	}
	host = strings.Trim(host, "[]")
	if host == "" || port == "" {
		return "", "", errors.New("dest must be in host:port format")
	}
	return host, port, nil
}

func generateRealityKeyPair() (string, string, error) {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate reality key pair: %w", err)
	}
	publicKey := privateKey.PublicKey()
	return base64.RawURLEncoding.EncodeToString(privateKey.Bytes()), base64.RawURLEncoding.EncodeToString(publicKey.Bytes()), nil
}

func publicKeyFromPrivate(privateKey string) (string, error) {
	raw, err := decodeKey(privateKey)
	if err != nil {
		return "", err
	}
	curve := ecdh.X25519()
	key, err := curve.NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("parse privateKey: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func decodeKey(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	decoders := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, encoding := range decoders {
		raw, err := encoding.DecodeString(trimmed)
		if err == nil {
			return raw, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("decode key: %w", lastErr)
}

func validateShortID(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	if len(trimmed)%2 != 0 || len(trimmed) > 16 {
		return errors.New("shortIds must be even-length hex strings up to 16 chars")
	}
	if _, err := hex.DecodeString(trimmed); err != nil {
		return errors.New("shortIds must be hexadecimal")
	}
	return nil
}

func generateUUID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16]), nil
}

func generateShortID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate shortId: %w", err)
	}
	return hex.EncodeToString(buf), nil
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
		return errors.New("xray management is only supported on linux")
	}
	if os.Geteuid() != 0 {
		return errors.New("xray management requires root privileges")
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
