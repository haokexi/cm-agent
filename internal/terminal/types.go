package terminal

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
