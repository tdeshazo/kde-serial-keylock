package screentime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	Store        *Store
	OnlineWindow time.Duration
}

type setRequest struct {
	Seconds     int    `json:"seconds"`
	DisplayName string `json:"display_name"`
}

type deviceStateRequest struct {
	UserID      string `json:"user_id"`
	DisplayName string `json:"display_name"`
	Locked      bool   `json:"locked"`
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("GET /v1/state", s.handleState)
	mux.HandleFunc("GET /v1/users/{user_id}/status", s.handleUserStatus)
	mux.HandleFunc("POST /v1/users/{user_id}/allowance/set", s.handleSet)
	mux.HandleFunc("POST /v1/users/{user_id}/allowance/add", s.handleAdd)
	mux.HandleFunc("POST /v1/users/{user_id}/allowance/clear", s.handleClear)
	mux.HandleFunc("POST /v1/devices/{device_id}/state", s.handleDeviceState)
	mux.HandleFunc("GET /v1/devices/{device_id}/policy", s.handleDevicePolicy)
	return mux
}

func (s Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s Server) handleState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.Snapshot(time.Now(), s.OnlineWindow))
}

func (s Server) handleUserStatus(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("user_id")
	writeJSON(w, http.StatusOK, s.Store.Status(userID, time.Now(), s.OnlineWindow))
}

func (s Server) handleSet(w http.ResponseWriter, r *http.Request) {
	var req setRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	status, err := s.Store.Set(r.PathValue("user_id"), req.DisplayName, req.Seconds, time.Now(), s.OnlineWindow)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s Server) handleAdd(w http.ResponseWriter, r *http.Request) {
	var req setRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	status, err := s.Store.Add(r.PathValue("user_id"), req.DisplayName, req.Seconds, time.Now(), s.OnlineWindow)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s Server) handleClear(w http.ResponseWriter, r *http.Request) {
	status, err := s.Store.Clear(r.PathValue("user_id"), time.Now(), s.OnlineWindow)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s Server) handleDeviceState(w http.ResponseWriter, r *http.Request) {
	var req deviceStateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	status, err := s.Store.ReportDevice(r.PathValue("device_id"), req.DisplayName, req.UserID, req.Locked, time.Now(), s.OnlineWindow)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s Server) handleDevicePolicy(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("device_id")
	snap := s.Store.Snapshot(time.Now(), s.OnlineWindow)
	device := snap.Devices[deviceID]
	if device == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("unknown device %q", deviceID))
		return
	}
	writeJSON(w, http.StatusOK, s.Store.Status(device.UserID, time.Now(), s.OnlineWindow))
}

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func (c Client) Status(ctx context.Context, userID string) (UserStatus, error) {
	var out UserStatus
	err := c.do(ctx, http.MethodGet, "/v1/users/"+userID+"/status", nil, &out)
	return out, err
}

func (c Client) Set(ctx context.Context, userID string, seconds int) (UserStatus, error) {
	return c.allowance(ctx, userID, "set", seconds)
}

func (c Client) Add(ctx context.Context, userID string, seconds int) (UserStatus, error) {
	return c.allowance(ctx, userID, "add", seconds)
}

func (c Client) Clear(ctx context.Context, userID string) (UserStatus, error) {
	var out UserStatus
	err := c.do(ctx, http.MethodPost, "/v1/users/"+userID+"/allowance/clear", map[string]any{}, &out)
	return out, err
}

func (c Client) ReportDevice(ctx context.Context, deviceID, displayName, userID string, locked bool) (UserStatus, error) {
	var out UserStatus
	body := deviceStateRequest{UserID: userID, DisplayName: displayName, Locked: locked}
	err := c.do(ctx, http.MethodPost, "/v1/devices/"+deviceID+"/state", body, &out)
	return out, err
}

func (c Client) State(ctx context.Context) (Snapshot, error) {
	var out Snapshot
	err := c.do(ctx, http.MethodGet, "/v1/state", nil, &out)
	return out, err
}

func (c Client) allowance(ctx context.Context, userID, op string, seconds int) (UserStatus, error) {
	var out UserStatus
	body := setRequest{Seconds: seconds}
	err := c.do(ctx, http.MethodPost, "/v1/users/"+userID+"/allowance/"+op, body, &out)
	return out, err
}

func (c Client) do(ctx context.Context, method, path string, body any, out any) error {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "http://127.0.0.1:8787"
	}
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s failed: status=%d body=%s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(out)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
