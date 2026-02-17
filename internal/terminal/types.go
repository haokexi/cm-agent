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

	// Used by network_test control message.
	TestID          string `json:"test_id,omitempty"`
	Role            string `json:"role,omitempty"` // server | client
	TargetHost      string `json:"target_host,omitempty"`
	Port            int    `json:"port,omitempty"`
	DurationSeconds int    `json:"duration_seconds,omitempty"`
	Parallel        int    `json:"parallel,omitempty"`
	Protocol        string `json:"protocol,omitempty"` // currently tcp
}

type ResizeMessage struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

type NetworkTestResultMessage struct {
	Type string `json:"type"` // network_test_result

	TestID   string `json:"test_id,omitempty"`
	Role     string `json:"role,omitempty"` // server | client
	Protocol string `json:"protocol,omitempty"`

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
}
