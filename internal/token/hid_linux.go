//go:build linux

package token

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type HIDInfo struct {
	Path string
	VID  string
	PID  string
	Name string
}

func ListHIDDevices() ([]HIDInfo, error) {
	matches, err := filepath.Glob("/dev/hidraw*")
	if err != nil {
		return nil, err
	}
	infos := make([]HIDInfo, 0, len(matches))
	for _, path := range matches {
		vid, pid, name := readHIDSysfs(path)
		infos = append(infos, HIDInfo{Path: path, VID: vid, PID: pid, Name: name})
	}
	return infos, nil
}

func (a Authenticator) authenticateHID(ctx context.Context) (string, error) {
	devices, err := a.candidateHIDDevices()
	if err != nil {
		return "", err
	}
	if len(devices) == 0 {
		return "", errors.New("no matching HID devices")
	}
	a.debug("hid auth candidates selected", "devices", devices)

	var lastErr error
	for _, path := range devices {
		if err := a.challengeHIDDevice(ctx, path); err != nil {
			lastErr = err
			continue
		}
		return path, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no HID devices attempted")
	}
	return "", lastErr
}

func (a Authenticator) diagnoseHID(ctx context.Context) (Diagnostic, error) {
	return a.hidDiagnosticCommand(ctx)
}

func (a Authenticator) timerStatusHID(ctx context.Context) (TimerStatus, error) {
	return a.hidTimerCommand(ctx, timerCommand+" STATUS")
}

func (a Authenticator) sendTimerCommandHID(ctx context.Context, commandParts ...string) (TimerStatus, error) {
	unsigned := strings.Join(append([]string{timerCommand}, commandParts...), " ")
	mac := hmacSHA256Hex(a.Secret, []byte(unsigned))
	return a.hidTimerCommand(ctx, unsigned+" "+mac)
}

func (a Authenticator) candidateHIDDevices() ([]string, error) {
	if a.Cfg.HIDPath != "" {
		return []string{a.Cfg.HIDPath}, nil
	}
	infos, err := ListHIDDevices()
	if err != nil {
		return nil, err
	}
	wantVID := strings.ToLower(a.Cfg.HIDVID)
	wantPID := strings.ToLower(a.Cfg.HIDPID)
	var paths []string
	for _, d := range infos {
		if wantVID != "" && strings.ToLower(d.VID) != wantVID {
			continue
		}
		if wantPID != "" && strings.ToLower(d.PID) != wantPID {
			continue
		}
		paths = append(paths, d.Path)
	}
	return paths, nil
}

func (a Authenticator) challengeHIDDevice(ctx context.Context, path string) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	challenge := "KEYLOCK/1 " + nonceHex
	a.debug("hid auth challenge generated", "device", path, "nonce_hex", nonceHex)

	line, err := a.hidExchangeLine(ctx, path, challenge)
	if err != nil {
		return fmt.Errorf("hid exchange with %s: %w", path, err)
	}
	result := verifyResponse(a.Secret, nonceHex, line)
	if a.Cfg.Debug {
		a.debug(
			"hid auth response verified",
			"device", path,
			"line", line,
			"protocol", result.protocol,
			"mac", result.macHex,
			"reason", result.reason,
			"expected_ascii_hmac", result.expectedASCIIHex,
			"expected_raw_hmac", result.expectedRawHex,
		)
	}
	if result.ok {
		return nil
	}
	return fmt.Errorf("bad HID token response from %s: %s", path, result.reason)
}

func (a Authenticator) hidDiagnosticCommand(ctx context.Context) (Diagnostic, error) {
	devices, err := a.candidateHIDDevices()
	if err != nil {
		return Diagnostic{}, err
	}
	if len(devices) == 0 {
		return Diagnostic{}, errors.New("no matching HID devices")
	}

	var lastErr error
	for _, path := range devices {
		diag, err := a.hidDiagnosticDevice(ctx, path)
		if err != nil {
			lastErr = err
			continue
		}
		return diag, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no HID devices attempted")
	}
	return Diagnostic{}, lastErr
}

func (a Authenticator) hidDiagnosticDevice(ctx context.Context, path string) (Diagnostic, error) {
	diag := Diagnostic{
		Port:            path,
		ExpectedKeyHash: sha256Hex(a.Secret),
		ExpectedTestMAC: hmacSHA256Hex(a.Secret, []byte(testVectorMessage)),
	}
	lines, err := a.hidExchangeLines(ctx, path, diagnosticCommand, 2)
	if err != nil {
		return diag, err
	}
	for _, line := range lines {
		if a.handleAsyncLine(path, line) {
			continue
		}
		diag.RawLines = append(diag.RawLines, line)
		fields := strings.Fields(stripBeforeKnownDiagnostic(line))
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case DiagnosticKeyHashPrefix:
			diag.KeyHash = fields[1]
		case DiagnosticTestMACPrefix:
			diag.TestMAC = fields[1]
		case "ERR":
			return diag, fmt.Errorf("token diagnostic command failed: %s", line)
		}
	}
	if diag.KeyHash != "" && diag.TestMAC != "" {
		return diag, nil
	}
	if len(diag.RawLines) == 0 {
		return diag, fmt.Errorf("no diagnostic response from %s", path)
	}
	return diag, fmt.Errorf("incomplete diagnostic response from %s", path)
}

func (a Authenticator) hidTimerCommand(ctx context.Context, line string) (TimerStatus, error) {
	devices, err := a.candidateHIDDevices()
	if err != nil {
		return TimerStatus{}, err
	}
	if len(devices) == 0 {
		return TimerStatus{}, errors.New("no matching HID devices")
	}

	var lastErr error
	for _, path := range devices {
		status, err := a.hidTimerCommandDevice(ctx, path, line)
		if err != nil {
			lastErr = err
			continue
		}
		return status, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no HID devices attempted")
	}
	return TimerStatus{}, lastErr
}

func (a Authenticator) hidTimerCommandDevice(ctx context.Context, path string, line string) (TimerStatus, error) {
	lines, err := a.hidExchangeLines(ctx, path, line, 4)
	if err != nil {
		return TimerStatus{}, err
	}
	var rejection string
	for _, response := range lines {
		response = strings.TrimSpace(response)
		if response == "" {
			continue
		}
		if a.handleAsyncLine(path, response) {
			continue
		}
		if strings.Contains(response, "ERR ") {
			rejection = response
			continue
		}
		parsed, ok := parseTimerStatusLine(path, response)
		if ok {
			return parsed, nil
		}
	}
	if rejection != "" {
		return TimerStatus{}, fmt.Errorf("timer command rejected by %s: %s", path, rejection)
	}
	return TimerStatus{}, fmt.Errorf("no timer response from %s", path)
}

func (a Authenticator) hidExchangeLine(ctx context.Context, path string, line string) (string, error) {
	lines, err := a.hidExchangeLines(ctx, path, line, 4)
	if err != nil {
		return "", err
	}
	for _, response := range lines {
		response = strings.TrimSpace(response)
		if response == "" {
			continue
		}
		if a.handleAsyncLine(path, response) {
			continue
		}
		return response, nil
	}
	return "", fmt.Errorf("no response from %s", path)
}

func (a Authenticator) hidExchangeLines(ctx context.Context, path string, line string, maxLines int) ([]string, error) {
	f, err := openNonblocking(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := a.writeHIDLine(ctx, f, line); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(a.Cfg.Timeout)
	var lines []string
	for len(lines) < maxLines {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if len(lines) > 0 {
				return lines, nil
			}
			return nil, errTimeout
		}
		response, err := a.readHIDLine(ctx, f, remaining)
		if err != nil {
			if errors.Is(err, errTimeout) && len(lines) > 0 {
				return lines, nil
			}
			return nil, err
		}
		if response != "" {
			lines = append(lines, response)
		}
	}
	return lines, nil
}

func (a Authenticator) writeHIDLine(ctx context.Context, f *os.File, line string) error {
	reportSize := a.hidReportSize()
	payloadSize := reportSize - 1
	if payloadSize < 2 {
		return errors.New("hid report size must leave room for length and payload")
	}
	payload := []byte(line)
	if len(payload) > payloadSize-1 {
		return fmt.Errorf("hid command too long: %d > %d", len(payload), payloadSize-1)
	}
	report := make([]byte, reportSize)
	report[0] = byte(a.hidReportID())
	report[1] = byte(len(payload))
	copy(report[2:], payload)
	return writeAll(ctx, f, report, a.Cfg.Timeout)
}

func (a Authenticator) readHIDLine(ctx context.Context, f *os.File, timeout time.Duration) (string, error) {
	reportSize := a.hidReportSize()
	buf := make([]byte, reportSize)
	deadline := time.Now().Add(timeout)
	for {
		if timeout > 0 && time.Now().After(deadline) {
			return "", errTimeout
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		n, err := f.Read(buf)
		if n > 0 {
			report := buf[:n]
			if len(report) == reportSize && report[0] == byte(a.hidReportID()) {
				report = report[1:]
			}
			if len(report) < 2 {
				continue
			}
			length := int(report[0])
			if length == 0 {
				continue
			}
			if length > len(report)-1 {
				length = len(report) - 1
			}
			return strings.TrimRight(string(report[1:1+length]), "\x00\r\n"), nil
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) || isAgain(err) {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		return "", err
	}
}

func (a Authenticator) hidReportID() int {
	if a.Cfg.HIDReportID == 0 {
		return 1
	}
	return a.Cfg.HIDReportID
}

func (a Authenticator) hidReportSize() int {
	if a.Cfg.HIDReportSize == 0 {
		return 128
	}
	return a.Cfg.HIDReportSize
}

func openNonblocking(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

func readHIDSysfs(path string) (vid, pid, name string) {
	base := filepath.Base(path)
	deviceDir := filepath.Join("/sys/class/hidraw", base, "device")
	for i := 0; i < 8; i++ {
		if b, err := os.ReadFile(filepath.Join(deviceDir, "uevent")); err == nil {
			fields := bytes.Split(b, []byte{'\n'})
			for _, field := range fields {
				key, value, ok := bytes.Cut(field, []byte{'='})
				if !ok {
					continue
				}
				switch string(key) {
				case "HID_NAME":
					name = strings.TrimSpace(string(value))
				case "HID_ID":
					parts := strings.Split(string(value), ":")
					if len(parts) == 3 {
						vid = normalizeHex(parts[1])
						pid = normalizeHex(parts[2])
					}
				}
			}
		}
		if b, err := os.ReadFile(filepath.Join(deviceDir, "idVendor")); err == nil {
			vid = normalizeHex(strings.TrimSpace(string(b)))
		}
		if b, err := os.ReadFile(filepath.Join(deviceDir, "idProduct")); err == nil {
			pid = normalizeHex(strings.TrimSpace(string(b)))
		}
		if vid != "" || pid != "" || name != "" {
			return vid, pid, name
		}
		next := filepath.Dir(deviceDir)
		if next == deviceDir || next == "." || next == "/" {
			break
		}
		deviceDir = next
	}
	return vid, pid, name
}

func normalizeHex(s string) string {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if n, err := strconv.ParseUint(s, 16, 32); err == nil {
		return fmt.Sprintf("%04x", n)
	}
	return s
}
