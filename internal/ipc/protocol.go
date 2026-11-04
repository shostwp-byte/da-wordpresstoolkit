package ipc

const (
	DefaultAdminSocketPath = "/var/run/da-wptoolkit.sock"
	DefaultUserSocketPath  = "/var/run/da-wptoolkit-user.sock"
	ProtocolVersion        = "1.0"
)

// Request is the newline-delimited JSON envelope sent over Admin or User Unix Domain Sockets.
type Request struct {
	Action     string         `json:"action"`
	Username   string         `json:"username,omitempty"`
	SessionID  string         `json:"session_id,omitempty"`
	CSRFToken  string         `json:"csrf_token,omitempty"`
	InstanceID string         `json:"instance_id,omitempty"`
	JobID      string         `json:"job_id,omitempty"`
	Limit      int            `json:"limit,omitempty"`
	Params     map[string]any `json:"params,omitempty"`
}

// Response is the single-line JSON reply emitted by da-wptoolkitd.
type Response struct {
	OK        bool   `json:"ok"`
	Code      int    `json:"code,omitempty"`
	Error     string `json:"error,omitempty"`
	CSRFToken string `json:"csrf_token,omitempty"`
	JobID     string `json:"job_id,omitempty"`
	Data      any    `json:"data,omitempty"`
}

// PingData reports daemon health, version, active kernel inotify watches, and uptime.
type PingData struct {
	Service         string `json:"service"`
	Version         string `json:"version"`
	ProtocolVersion string `json:"protocol_version"`
	UptimeSeconds   int64  `json:"uptime_seconds"`
	ManagedSites    int    `json:"managed_sites"`
	InotifyWatches  int    `json:"inotify_watches"`
	WebServer       string `json:"web_server,omitempty"`
}
