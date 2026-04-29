package screentime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type TimerState string

const (
	StateUnset   TimerState = "unset"
	StatePaused  TimerState = "paused"
	StateRunning TimerState = "running"
	StateExpired TimerState = "expired"
)

type User struct {
	ID               string     `json:"id"`
	DisplayName      string     `json:"display_name"`
	RemainingSeconds int        `json:"remaining_seconds"`
	State            TimerState `json:"state"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type Device struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	UserID      string    `json:"user_id"`
	Locked      bool      `json:"locked"`
	LastSeen    time.Time `json:"last_seen"`
}

type Snapshot struct {
	Users   map[string]*User   `json:"users"`
	Devices map[string]*Device `json:"devices"`
}

type UserStatus struct {
	UserID           string     `json:"user_id"`
	State            TimerState `json:"state"`
	RemainingSeconds int        `json:"remaining_seconds"`
	ShouldLock       bool       `json:"should_lock"`
	ActiveDevices    []string   `json:"active_devices,omitempty"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type Store struct {
	mu   sync.Mutex
	path string
	data Snapshot
}

func Load(path string) (*Store, error) {
	s := &Store{path: path, data: emptySnapshot()}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read screen-time state: %w", err)
	}
	if len(b) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("parse screen-time state: %w", err)
	}
	s.normalize(time.Now())
	return s, nil
}

func emptySnapshot() Snapshot {
	return Snapshot{
		Users:   map[string]*User{},
		Devices: map[string]*Device{},
	}
}

func (s *Store) Snapshot(now time.Time, onlineWindow time.Duration) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickLocked(now, onlineWindow)
	return cloneSnapshot(s.data)
}

func (s *Store) Status(userID string, now time.Time, onlineWindow time.Duration) UserStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickLocked(now, onlineWindow)
	return s.statusLocked(userID, now, onlineWindow)
}

func (s *Store) Set(userID, displayName string, seconds int, now time.Time, onlineWindow time.Duration) (UserStatus, error) {
	if userID == "" {
		return UserStatus{}, errors.New("user_id is required")
	}
	if seconds < 0 {
		return UserStatus{}, errors.New("seconds cannot be negative")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickLocked(now, onlineWindow)
	u := s.ensureUserLocked(userID, displayName, now)
	u.RemainingSeconds = seconds
	u.State = StateUnset
	if seconds > 0 {
		u.State = StatePaused
	}
	u.UpdatedAt = now
	s.recalculateUserStateLocked(u, now, onlineWindow)
	if err := s.saveLocked(); err != nil {
		return UserStatus{}, err
	}
	return s.statusLocked(userID, now, onlineWindow), nil
}

func (s *Store) Add(userID, displayName string, seconds int, now time.Time, onlineWindow time.Duration) (UserStatus, error) {
	if userID == "" {
		return UserStatus{}, errors.New("user_id is required")
	}
	if seconds < 0 {
		return UserStatus{}, errors.New("seconds cannot be negative")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickLocked(now, onlineWindow)
	u := s.ensureUserLocked(userID, displayName, now)
	u.RemainingSeconds += seconds
	if u.RemainingSeconds <= 0 {
		u.RemainingSeconds = 0
		u.State = StateUnset
	} else if u.State == StateUnset || u.State == StateExpired {
		u.State = StatePaused
	}
	u.UpdatedAt = now
	s.recalculateUserStateLocked(u, now, onlineWindow)
	if err := s.saveLocked(); err != nil {
		return UserStatus{}, err
	}
	return s.statusLocked(userID, now, onlineWindow), nil
}

func (s *Store) Clear(userID string, now time.Time, onlineWindow time.Duration) (UserStatus, error) {
	if userID == "" {
		return UserStatus{}, errors.New("user_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickLocked(now, onlineWindow)
	u := s.ensureUserLocked(userID, "", now)
	u.RemainingSeconds = 0
	u.State = StateUnset
	u.UpdatedAt = now
	if err := s.saveLocked(); err != nil {
		return UserStatus{}, err
	}
	return s.statusLocked(userID, now, onlineWindow), nil
}

func (s *Store) ReportDevice(deviceID, displayName, userID string, locked bool, now time.Time, onlineWindow time.Duration) (UserStatus, error) {
	if deviceID == "" {
		return UserStatus{}, errors.New("device_id is required")
	}
	if userID == "" {
		return UserStatus{}, errors.New("user_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickLocked(now, onlineWindow)
	s.ensureUserLocked(userID, userID, now)
	d := s.data.Devices[deviceID]
	if d == nil {
		d = &Device{ID: deviceID}
		s.data.Devices[deviceID] = d
	}
	d.DisplayName = displayName
	if d.DisplayName == "" {
		d.DisplayName = deviceID
	}
	d.UserID = userID
	d.Locked = locked
	d.LastSeen = now
	if u := s.data.Users[userID]; u != nil {
		s.recalculateUserStateLocked(u, now, onlineWindow)
	}
	if err := s.saveLocked(); err != nil {
		return UserStatus{}, err
	}
	return s.statusLocked(userID, now, onlineWindow), nil
}

func (s *Store) normalize(now time.Time) {
	if s.data.Users == nil {
		s.data.Users = map[string]*User{}
	}
	if s.data.Devices == nil {
		s.data.Devices = map[string]*Device{}
	}
	for id, u := range s.data.Users {
		if u == nil {
			delete(s.data.Users, id)
			continue
		}
		if u.ID == "" {
			u.ID = id
		}
		if u.DisplayName == "" {
			u.DisplayName = u.ID
		}
		if u.UpdatedAt.IsZero() {
			u.UpdatedAt = now
		}
		if u.RemainingSeconds < 0 {
			u.RemainingSeconds = 0
		}
		if u.State == "" {
			u.State = StateUnset
			if u.RemainingSeconds > 0 {
				u.State = StatePaused
			}
		}
	}
	for id, d := range s.data.Devices {
		if d == nil {
			delete(s.data.Devices, id)
			continue
		}
		if d.ID == "" {
			d.ID = id
		}
		if d.DisplayName == "" {
			d.DisplayName = d.ID
		}
	}
}

func (s *Store) ensureUserLocked(userID, displayName string, now time.Time) *User {
	u := s.data.Users[userID]
	if u == nil {
		u = &User{ID: userID, DisplayName: displayName, State: StateUnset, UpdatedAt: now}
		s.data.Users[userID] = u
	}
	if u.DisplayName == "" || u.DisplayName == u.ID {
		if displayName != "" {
			u.DisplayName = displayName
		} else if u.DisplayName == "" {
			u.DisplayName = userID
		}
	}
	return u
}

func (s *Store) tickLocked(now time.Time, onlineWindow time.Duration) {
	if onlineWindow <= 0 {
		onlineWindow = 10 * time.Second
	}
	for _, u := range s.data.Users {
		if u == nil {
			continue
		}
		if u.State == StateRunning && !u.UpdatedAt.IsZero() {
			elapsed := int(now.Sub(u.UpdatedAt).Seconds())
			if elapsed > 0 {
				u.RemainingSeconds -= elapsed
				u.UpdatedAt = u.UpdatedAt.Add(time.Duration(elapsed) * time.Second)
			}
		}
		if u.RemainingSeconds <= 0 {
			u.RemainingSeconds = 0
			if u.State != StateUnset {
				u.State = StateExpired
				u.UpdatedAt = now
			}
			continue
		}
		s.recalculateUserStateLocked(u, now, onlineWindow)
	}
}

func (s *Store) recalculateUserStateLocked(u *User, now time.Time, onlineWindow time.Duration) {
	if u == nil || u.RemainingSeconds <= 0 {
		return
	}
	active := len(s.activeDevicesLocked(u.ID, now, onlineWindow)) > 0
	want := StatePaused
	if active {
		want = StateRunning
	}
	if u.State != want {
		u.State = want
		u.UpdatedAt = now
	}
}

func (s *Store) activeDevicesLocked(userID string, now time.Time, onlineWindow time.Duration) []string {
	var active []string
	for _, d := range s.data.Devices {
		if d == nil || d.UserID != userID || d.Locked {
			continue
		}
		if !d.LastSeen.IsZero() && now.Sub(d.LastSeen) <= onlineWindow {
			active = append(active, d.ID)
		}
	}
	return active
}

func (s *Store) statusLocked(userID string, now time.Time, onlineWindow time.Duration) UserStatus {
	u := s.data.Users[userID]
	if u == nil {
		return UserStatus{UserID: userID, State: StateUnset, ShouldLock: true, UpdatedAt: now}
	}
	state := u.State
	shouldLock := state == StateExpired || (state == StateUnset && u.RemainingSeconds <= 0)
	return UserStatus{
		UserID:           u.ID,
		State:            state,
		RemainingSeconds: u.RemainingSeconds,
		ShouldLock:       shouldLock,
		ActiveDevices:    s.activeDevicesLocked(userID, now, onlineWindow),
		UpdatedAt:        u.UpdatedAt,
	}
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil && filepath.Dir(s.path) != "." {
		return fmt.Errorf("create screen-time state dir: %w", err)
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode screen-time state: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write screen-time state: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace screen-time state: %w", err)
	}
	return nil
}

func cloneSnapshot(in Snapshot) Snapshot {
	out := emptySnapshot()
	for id, u := range in.Users {
		if u == nil {
			continue
		}
		copyUser := *u
		out.Users[id] = &copyUser
	}
	for id, d := range in.Devices {
		if d == nil {
			continue
		}
		copyDevice := *d
		out.Devices[id] = &copyDevice
	}
	return out
}
