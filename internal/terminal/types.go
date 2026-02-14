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
}

type ResizeMessage struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}
