package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Client sends CLI / Hook requests to da-wptoolkitd over the Admin Unix Domain Socket.
type Client struct {
	SocketPath string
	Timeout    time.Duration
}

func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = DefaultAdminSocketPath
	}
	return &Client{
		SocketPath: socketPath,
		Timeout:    15 * time.Second,
	}
}

func (c *Client) Send(ctx context.Context, req Request) (Response, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return Response{}, fmt.Errorf("connect socket %s: %w", c.SocketPath, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	payload = append(payload, '\n')
	if _, err := conn.Write(payload); err != nil {
		return Response{}, err
	}

	rd := bufio.NewReader(conn)
	line, err := rd.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return Response{}, err
	}

	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("invalid daemon response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "daemon returned unsuccessful status"
		}
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}
