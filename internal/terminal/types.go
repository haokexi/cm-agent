package terminal

import (
	"cm-agent/internal/realm"
	"cm-agent/internal/ssrust"
	"cm-agent/internal/xray"
)

// ControlMessage is sent from server to agent over the control WS.
// Keep this compatible with the server's JSON schema.
type ControlMessage struct {
	Type string `json:"type"`

	SessionID string `json:"session_id"`

	// One-time token used to connect to the terminal WS for this session.
	AgentSessionToken string `json:"agent_session_token"`

	// Optional override terminal WS URL for this session.
	TerminalWSURL string `json:"terminal_ws_url,omitempty"`

	Cols int `json:"cols"`
	Rows int `json:"rows"`

	// Used by sync_labels control message.
	Labels  map[string]string `json:"labels,omitempty"`
	Version int64             `json:"version,omitempty"`

	// Used by sync_probes control message.
	Probes []ProbeRule `json:"probes,omitempty"`

	// Used by network_test control message.
	TestID          string `json:"test_id,omitempty"`
	RootTestID      string `json:"root_test_id,omitempty"`
	Direction       string `json:"direction,omitempty"` // forward | reverse
	Role            string `json:"role,omitempty"`      // server | client
	TargetHost      string `json:"target_host,omitempty"`
	Port            int    `json:"port,omitempty"`
	DurationSeconds int    `json:"duration_seconds,omitempty"`
	Parallel        int    `json:"parallel,omitempty"`
	Protocol        string `json:"protocol,omitempty"` // currently tcp
	Reverse         bool   `json:"reverse,omitempty"`  // client uses -R flag

	// Used by upgrade_agent control message.
	UpdateRequestID string `json:"update_request_id,omitempty"`
	TargetVersion   string `json:"target_version,omitempty"` // empty/latest -> latest release
	ReleaseRepo     string `json:"release_repo,omitempty"`   // owner/repo, fallback to agent default
	GitHubProxy     string `json:"github_proxy,omitempty"`   // optional proxy prefix

	// Used by ssrust_task control message.
	SSRustRequestID    string         `json:"ssrust_request_id,omitempty"`
	SSRustAction       string         `json:"ssrust_action,omitempty"`
	SSRustVersion      string         `json:"ssrust_version,omitempty"`
	SSRustOpenFirewall bool           `json:"ssrust_open_firewall,omitempty"`
	SSRustConfig       *ssrust.Config `json:"ssrust_config,omitempty"`

	// Used by xray_task control message.
	XrayRequestID    string       `json:"xray_request_id,omitempty"`
	XrayAction       string       `json:"xray_action,omitempty"`
	XrayVersion      string       `json:"xray_version,omitempty"`
	XrayOpenFirewall bool         `json:"xray_open_firewall,omitempty"`
	XrayConfig       *xray.Config `json:"xray_config,omitempty"`

	// Used by realm_task control message.
	RealmRequestID string        `json:"realm_request_id,omitempty"`
	RealmAction    string        `json:"realm_action,omitempty"`
	RealmVersion   string        `json:"realm_version,omitempty"`
	RealmConfig    *realm.Config `json:"realm_config,omitempty"`

	// Used by realm_rule_test control message.
	RealmRuleTestRequestID string `json:"realm_rule_test_request_id,omitempty"`
	RealmRuleTestListen    string `json:"realm_rule_test_listen,omitempty"`
	RealmRuleTestRemote    string `json:"realm_rule_test_remote,omitempty"`
}

type ProbeRule struct {
	RuleID          string `json:"rule_id,omitempty"`
	Module          string `json:"module,omitempty"`      // icmp | tcp_connect
	Target          string `json:"target,omitempty"`      // host or host:port
	IPProtocol      string `json:"ip_protocol,omitempty"` // auto | ipv4 | ipv6 (icmp only)
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
	TimeoutMs       int    `json:"timeout_ms,omitempty"`
	Enabled         bool   `json:"enabled,omitempty"`
}

type ResizeMessage struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

type NetworkTestResultMessage struct {
	Type string `json:"type"` // network_test_result

	TestID     string `json:"test_id,omitempty"`
	RootTestID string `json:"root_test_id,omitempty"`
	Direction  string `json:"direction,omitempty"` // forward | reverse
	Role       string `json:"role,omitempty"`      // server | client
	Protocol   string `json:"protocol,omitempty"`

	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`

	TargetHost string `json:"target_host,omitempty"`
	Port       int    `json:"port,omitempty"`

	DurationSeconds int `json:"duration_seconds,omitempty"`
	Parallel        int `json:"parallel,omitempty"`

	BitsPerSecond float64 `json:"bps,omitempty"`
	Bytes         int64   `json:"bytes,omitempty"`
	Retransmits   int64   `json:"retransmits,omitempty"`
	JitterMs      float64 `json:"jitter_ms,omitempty"`
	LostPercent   float64 `json:"lost_percent,omitempty"`

	SummaryLine string `json:"summary_line,omitempty"`
}

type NetworkTestProgressMessage struct {
	Type string `json:"type"` // network_test_progress

	TestID     string `json:"test_id,omitempty"`
	RootTestID string `json:"root_test_id,omitempty"`
	Direction  string `json:"direction,omitempty"` // forward | reverse
	Role       string `json:"role,omitempty"`      // client
	Protocol   string `json:"protocol,omitempty"`

	TargetHost string `json:"target_host,omitempty"`
	Port       int    `json:"port,omitempty"`

	DurationSeconds int `json:"duration_seconds,omitempty"`
	Parallel        int `json:"parallel,omitempty"`

	IntervalStartSec float64 `json:"interval_start_sec,omitempty"`
	IntervalEndSec   float64 `json:"interval_end_sec,omitempty"`
	BitsPerSecond    float64 `json:"bps,omitempty"`
	Bytes            int64   `json:"bytes,omitempty"`
	Retransmits      int64   `json:"retransmits,omitempty"`
	IsSummary        bool    `json:"is_summary,omitempty"`

	RawLine     string `json:"raw_line,omitempty"`
	TimestampMs int64  `json:"timestamp_ms,omitempty"`
}

type AgentUpdateResultMessage struct {
	Type string `json:"type"` // agent_update_result

	UpdateRequestID string `json:"update_request_id,omitempty"`
	Success         bool   `json:"success"`
	Error           string `json:"error,omitempty"`

	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version,omitempty"`
	AssetName   string `json:"asset_name,omitempty"`
	AssetURL    string `json:"asset_url,omitempty"`

	StartedAtMs  int64 `json:"started_at_ms,omitempty"`
	FinishedAtMs int64 `json:"finished_at_ms,omitempty"`
}

type SSRustTaskResultMessage struct {
	Type string `json:"type"` // ssrust_task_result

	RequestID string `json:"request_id,omitempty"`
	Action    string `json:"action,omitempty"`

	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`

	Installed bool           `json:"installed"`
	Running   bool           `json:"running"`
	Version   string         `json:"version,omitempty"`
	Config    *ssrust.Config `json:"config,omitempty"`

	ServiceName string `json:"service_name,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	ConfigPath  string `json:"config_path,omitempty"`

	StartedAtMs  int64 `json:"started_at_ms,omitempty"`
	FinishedAtMs int64 `json:"finished_at_ms,omitempty"`
}

type XrayTaskResultMessage struct {
	Type string `json:"type"` // xray_task_result

	RequestID string `json:"request_id,omitempty"`
	Action    string `json:"action,omitempty"`

	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`

	Installed bool         `json:"installed"`
	Running   bool         `json:"running"`
	Version   string       `json:"version,omitempty"`
	Config    *xray.Config `json:"config,omitempty"`

	ServiceName string `json:"service_name,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	ConfigPath  string `json:"config_path,omitempty"`

	StartedAtMs  int64 `json:"started_at_ms,omitempty"`
	FinishedAtMs int64 `json:"finished_at_ms,omitempty"`
}

type RealmTaskResultMessage struct {
	Type string `json:"type"` // realm_task_result

	RequestID string `json:"request_id,omitempty"`
	Action    string `json:"action,omitempty"`

	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`

	Installed bool          `json:"installed"`
	Running   bool          `json:"running"`
	Version   string        `json:"version,omitempty"`
	Config    *realm.Config `json:"config,omitempty"`

	ServiceName string `json:"service_name,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	ConfigPath  string `json:"config_path,omitempty"`

	StartedAtMs  int64 `json:"started_at_ms,omitempty"`
	FinishedAtMs int64 `json:"finished_at_ms,omitempty"`
}

type RealmRuleTestResultMessage struct {
	Type string `json:"type"` // realm_rule_test_result

	RequestID string `json:"request_id,omitempty"`

	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`

	ListenAddress    string `json:"listen_address,omitempty"`
	RemoteAddress    string `json:"remote_address,omitempty"`
	ListenReachable  bool   `json:"listen_reachable"`
	RemoteReachable  bool   `json:"remote_reachable"`
	ListenTestTarget string `json:"listen_test_target,omitempty"`
	ListenError      string `json:"listen_error,omitempty"`
	RemoteError      string `json:"remote_error,omitempty"`

	StartedAtMs  int64 `json:"started_at_ms,omitempty"`
	FinishedAtMs int64 `json:"finished_at_ms,omitempty"`
}
