package ipc

import (
	"bytes"
	"encoding/json"
	"errors"
)

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

// UnmarshalJSON decodes Request while tolerating PHP's json_encode([]) quirk where an empty
// associative map is serialized as a JSON empty array `[]` instead of `{}`.
func (r *Request) UnmarshalJSON(data []byte) error {
	type rawRequest struct {
		Action     string          `json:"action"`
		Username   string          `json:"username,omitempty"`
		SessionID  string          `json:"session_id,omitempty"`
		CSRFToken  string          `json:"csrf_token,omitempty"`
		InstanceID string          `json:"instance_id,omitempty"`
		JobID      string          `json:"job_id,omitempty"`
		Limit      int             `json:"limit,omitempty"`
		Params     json.RawMessage `json:"params,omitempty"`
	}
	var raw rawRequest
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Action = raw.Action
	r.Username = raw.Username
	r.SessionID = raw.SessionID
	r.CSRFToken = raw.CSRFToken
	r.InstanceID = raw.InstanceID
	r.JobID = raw.JobID
	r.Limit = raw.Limit
	r.Params = nil

	trimmed := bytes.TrimSpace(raw.Params)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] == '[' {
		var arr []any
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return err
		}
		if len(arr) == 0 {
			r.Params = make(map[string]any)
			return nil
		}
		return errors.New("params field must be a JSON object")
	}
	var m map[string]any
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return err
	}
	r.Params = m
	return nil
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
