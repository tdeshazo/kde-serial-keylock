package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Config struct {
	// Transport selects how the host talks to the token. Empty defaults to serial
	// for backward compatibility with existing config files.
	Transport string       `json:"transport"`
	Serial    SerialConfig `json:"serial"`
	HID       HIDConfig    `json:"hid"`
	Auth      AuthConfig   `json:"auth"`
	Locker    LockerConfig `json:"locker"`
}

type SerialConfig struct {
	// Port is optional. If empty, keylock scans available serial ports.
	Port string `json:"port"`
	Baud int    `json:"baud"`
	// VID and PID are optional USB filters, expressed as lowercase or uppercase hex strings,
	// for example "2341" and "0043". Leave blank to accept any serial port that answers.
	VID                string `json:"vid"`
	PID                string `json:"pid"`
	PollIntervalMS     int    `json:"poll_interval_ms"`
	ChallengeTimeoutMS int    `json:"challenge_timeout_ms"`
}

type HIDConfig struct {
	// Path is optional. If empty, keylock scans /dev/hidraw* devices.
	Path string `json:"path"`
	// VID and PID are optional USB filters, expressed as lowercase or uppercase hex strings,
	// for example "239a" and "80f4". Leave blank to accept any HID device that answers.
	VID string `json:"vid"`
	PID string `json:"pid"`
	// ReportID and ReportSize must match the vendor HID descriptor in firmware/hid/boot.py.
	ReportID   int `json:"report_id"`
	ReportSize int `json:"report_size"`
}

type AuthConfig struct {
	// SecretEnv names the environment variable containing the shared secret.
	// Do not commit the secret to this JSON file.
	SecretEnv string `json:"secret_env"`
}

type LockerConfig struct {
	// Backend values:
	//   kde         - lock through KDE org.freedesktop.ScreenSaver; no external unlock attempt
	//   logind      - lock/unlock through loginctl
	//   kde-logind  - lock through KDE; unlock through loginctl
	Backend                 string `json:"backend"`
	RelockIntervalMS        int    `json:"relock_interval_ms"`
	UnlockWhenAuthenticated bool   `json:"unlock_when_authenticated"`
	DryRun                  bool   `json:"dry_run"`
}

func Default() Config {
	return Config{
		Transport: "serial",
		Serial: SerialConfig{
			Baud:               115200,
			PollIntervalMS:     1000,
			ChallengeTimeoutMS: 1500,
		},
		HID: HIDConfig{
			ReportID:   1,
			ReportSize: 64,
		},
		Auth: AuthConfig{SecretEnv: "KEYLOCK_SECRET"},
		Locker: LockerConfig{
			Backend:                 "kde-logind",
			RelockIntervalMS:        2000,
			UnlockWhenAuthenticated: true,
			DryRun:                  true,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Transport == "" {
		c.Transport = "serial"
	}
	if c.Serial.Baud == 0 {
		c.Serial.Baud = 115200
	}
	if c.Serial.PollIntervalMS == 0 {
		c.Serial.PollIntervalMS = 1000
	}
	if c.Serial.ChallengeTimeoutMS == 0 {
		c.Serial.ChallengeTimeoutMS = 1500
	}
	if c.HID.ReportID == 0 {
		c.HID.ReportID = 1
	}
	if c.HID.ReportSize == 0 {
		c.HID.ReportSize = 64
	}
	if c.Auth.SecretEnv == "" {
		c.Auth.SecretEnv = "KEYLOCK_SECRET"
	}
	if c.Locker.Backend == "" {
		c.Locker.Backend = "kde-logind"
	}
	if c.Locker.RelockIntervalMS == 0 {
		c.Locker.RelockIntervalMS = 2000
	}
}

func (c Config) PollInterval() time.Duration {
	return time.Duration(c.Serial.PollIntervalMS) * time.Millisecond
}

func (c Config) ChallengeTimeout() time.Duration {
	return time.Duration(c.Serial.ChallengeTimeoutMS) * time.Millisecond
}

func (c Config) RelockInterval() time.Duration {
	return time.Duration(c.Locker.RelockIntervalMS) * time.Millisecond
}
