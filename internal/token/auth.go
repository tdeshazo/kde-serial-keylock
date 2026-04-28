package token

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	diagnosticCommand = "KEYLOCK-DIAG/1"
	testVectorMessage = "KEYLOCK-TEST-NONCE"
)

const (
	DiagnosticKeyHashPrefix   = "KEY-SHA256"
	DiagnosticTestMACPrefix   = "TEST-HMAC-SHA256"
	DiagnosticUnsupportedLine = "ERR unsupported command"
)

var errTimeout = errors.New("timeout")

type Config struct {
	Port    string
	Baud    int
	VID     string
	PID     string
	Timeout time.Duration
	Debug   bool
}

type Authenticator struct {
	Cfg    Config
	Secret []byte
}

type PortInfo struct {
	Name    string
	Symlink string
	VID     string
	PID     string
}

type Diagnostic struct {
	Port            string
	KeyHash         string
	ExpectedKeyHash string
	TestMAC         string
	ExpectedTestMAC string
	RawLines        []string
}

func (d Diagnostic) KeyHashMatches() bool {
	return d.KeyHash != "" && strings.EqualFold(d.KeyHash, d.ExpectedKeyHash)
}

func (d Diagnostic) TestMACMatches() bool {
	return d.TestMAC != "" && strings.EqualFold(d.TestMAC, d.ExpectedTestMAC)
}

func ListPorts() ([]PortInfo, error) {
	seen := map[string]PortInfo{}
	patterns := []string{"/dev/serial/by-id/*", "/dev/ttyACM*", "/dev/ttyUSB*"}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			resolved, err := filepath.EvalSymlinks(m)
			if err != nil {
				resolved = m
			}
			vid, pid := readUSBIDs(resolved)
			info := PortInfo{Name: resolved, VID: vid, PID: pid}
			if resolved != m {
				info.Symlink = m
			}
			seen[resolved] = info
		}
	}
	out := make([]PortInfo, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	return out, nil
}

func (a Authenticator) Authenticate(ctx context.Context) (string, error) {
	if len(a.Secret) == 0 {
		return "", errors.New("empty secret")
	}
	ports, err := a.candidatePorts()
	if err != nil {
		return "", err
	}
	if len(ports) == 0 {
		return "", errors.New("no matching serial ports")
	}
	a.debugf("auth candidates: %s", strings.Join(ports, ", "))

	var lastErr error
	for _, name := range ports {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		if err := a.challengePort(ctx, name); err != nil {
			lastErr = err
			continue
		}
		return name, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no serial ports attempted")
	}
	return "", lastErr
}

func (a Authenticator) Diagnose(ctx context.Context) (Diagnostic, error) {
	if len(a.Secret) == 0 {
		return Diagnostic{}, errors.New("empty secret")
	}
	ports, err := a.candidatePorts()
	if err != nil {
		return Diagnostic{}, err
	}
	if len(ports) == 0 {
		return Diagnostic{}, errors.New("no matching serial ports")
	}
	a.debugf("auth diagnostic candidates: %s", strings.Join(ports, ", "))

	var lastErr error
	for _, name := range ports {
		diag, err := a.diagnosePort(ctx, name)
		if err != nil {
			lastErr = err
			continue
		}
		return diag, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no serial ports attempted")
	}
	return Diagnostic{}, lastErr
}

func (a Authenticator) candidatePorts() ([]string, error) {
	if a.Cfg.Port != "" {
		return []string{a.Cfg.Port}, nil
	}
	infos, err := ListPorts()
	if err != nil {
		return nil, err
	}
	wantVID := strings.ToLower(a.Cfg.VID)
	wantPID := strings.ToLower(a.Cfg.PID)
	var names []string
	for _, p := range infos {
		if wantVID != "" && strings.ToLower(p.VID) != wantVID {
			continue
		}
		if wantPID != "" && strings.ToLower(p.PID) != wantPID {
			continue
		}
		names = append(names, p.Name)
	}
	return names, nil
}

func (a Authenticator) challengePort(ctx context.Context, name string) error {
	a.debugf("auth %s: configuring tty baud=%d timeout=%s", name, a.Cfg.Baud, a.Cfg.Timeout)
	if err := configureTTY(ctx, name, a.Cfg.Baud); err != nil {
		return err
	}

	fd, err := syscall.Open(name, syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	challenge := []byte("KEYLOCK/1 " + nonceHex + "\n")
	a.debugf("auth %s: challenge nonce_hex=%s", name, nonceHex)
	if err := writeAll(ctx, f, challenge, a.Cfg.Timeout); err != nil {
		return fmt.Errorf("write challenge to %s: %w", name, err)
	}
	a.debugf("auth %s: challenge written bytes=%q", name, string(challenge))

	line, err := readLine(ctx, f, a.Cfg.Timeout)
	if err != nil {
		return fmt.Errorf("read response from %s: %w", name, err)
	}
	line = strings.TrimSpace(line)
	result := verifyResponse(a.Secret, nonceHex, line)
	if a.Cfg.Debug {
		a.debugf("auth %s: response line=%q", name, line)
		a.debugf("auth %s: response parsed protocol=%q mac=%q reason=%q", name, result.protocol, result.macHex, result.reason)
		a.debugf("auth %s: expected mac over ascii nonce=%s", name, result.expectedASCIIHex)
		if result.expectedRawHex != "" {
			a.debugf("auth %s: expected mac over raw nonce bytes=%s", name, result.expectedRawHex)
		}
	}
	if result.ok {
		return nil
	}
	return fmt.Errorf("bad token response from %s: %s", name, result.reason)
}

func (a Authenticator) diagnosePort(ctx context.Context, name string) (Diagnostic, error) {
	a.debugf("auth diagnostic %s: configuring tty baud=%d timeout=%s", name, a.Cfg.Baud, a.Cfg.Timeout)
	if err := configureTTY(ctx, name, a.Cfg.Baud); err != nil {
		return Diagnostic{}, err
	}

	fd, err := syscall.Open(name, syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Diagnostic{}, fmt.Errorf("open %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()

	command := []byte(diagnosticCommand + "\n")
	if err := writeAll(ctx, f, command, a.Cfg.Timeout); err != nil {
		return Diagnostic{}, fmt.Errorf("write diagnostic command to %s: %w", name, err)
	}
	a.debugf("auth diagnostic %s: command written bytes=%q", name, string(command))

	diag := Diagnostic{
		Port:            name,
		ExpectedKeyHash: sha256Hex(a.Secret),
		ExpectedTestMAC: hmacSHA256Hex(a.Secret, []byte(testVectorMessage)),
	}
	deadline := time.Now().Add(a.Cfg.Timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		line, err := readLine(ctx, f, remaining)
		if err != nil {
			if errors.Is(err, errTimeout) {
				break
			}
			return diag, fmt.Errorf("read diagnostic response from %s: %w", name, err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		diag.RawLines = append(diag.RawLines, line)
		a.debugf("auth diagnostic %s: response line=%q", name, line)
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
		if diag.KeyHash != "" && diag.TestMAC != "" {
			return diag, nil
		}
	}
	if len(diag.RawLines) == 0 {
		return diag, fmt.Errorf("no diagnostic response from %s", name)
	}
	return diag, fmt.Errorf("incomplete diagnostic response from %s", name)
}

func (a Authenticator) debugf(format string, args ...any) {
	if a.Cfg.Debug {
		log.Printf(format, args...)
	}
}

func stripBeforeKnownDiagnostic(line string) string {
	for _, marker := range []string{DiagnosticKeyHashPrefix, DiagnosticTestMACPrefix, "ERR "} {
		if idx := strings.Index(line, marker); idx >= 0 {
			return line[idx:]
		}
	}
	return line
}

func configureTTY(ctx context.Context, name string, baud int) error {
	if baud == 0 {
		baud = 115200
	}
	args := []string{"-F", name, strconv.Itoa(baud), "raw", "-echo", "-icanon", "min", "0", "time", "1"}
	cmd := exec.CommandContext(ctx, "stty", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("stty %v failed: %w: %s", args, err, string(out))
	}
	return nil
}

func writeAll(ctx context.Context, f *os.File, b []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for len(b) > 0 {
		if timeout > 0 && time.Now().After(deadline) {
			return errTimeout
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := f.Write(b)
		if n > 0 {
			b = b[n:]
		}
		if err == nil {
			continue
		}
		if isAgain(err) {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		return err
	}
	return nil
}

func readLine(ctx context.Context, f *os.File, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 256)
	var acc bytes.Buffer
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
			chunk := buf[:n]
			if idx := bytes.IndexByte(chunk, '\n'); idx >= 0 {
				acc.Write(chunk[:idx+1])
				return acc.String(), nil
			}
			acc.Write(chunk)
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

func isAgain(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
}

type verificationResult struct {
	ok               bool
	reason           string
	protocol         string
	macHex           string
	expectedASCIIHex string
	expectedRawHex   string
}

func verifyResponse(secret []byte, nonceHex string, line string) verificationResult {
	result := verificationResult{
		reason:           "hmac mismatch",
		expectedASCIIHex: hmacSHA256Hex(secret, []byte(nonceHex)),
	}
	if rawNonce, err := hex.DecodeString(nonceHex); err == nil {
		result.expectedRawHex = hmacSHA256Hex(secret, rawNonce)
	}

	fields := strings.Fields(line)
	switch len(fields) {
	case 1:
		result.macHex = fields[0]
	default:
		if idx := strings.Index(line, "HMAC-SHA256"); idx >= 0 {
			fields = strings.Fields(line[idx:])
		}
	}

	switch len(fields) {
	case 1:
		result.macHex = fields[0]
	case 2:
		result.protocol = fields[0]
		if fields[0] != "HMAC-SHA256" {
			result.reason = "unsupported response protocol"
			return result
		}
		result.macHex = fields[1]
	default:
		result.reason = "malformed response"
		return result
	}
	got, err := hex.DecodeString(result.macHex)
	if err != nil {
		result.reason = "response mac is not hex"
		return result
	}
	want, _ := hex.DecodeString(result.expectedASCIIHex)
	result.ok = hmac.Equal(got, want)
	if result.ok {
		result.reason = "ok"
		return result
	}
	if result.expectedRawHex != "" {
		rawWant, _ := hex.DecodeString(result.expectedRawHex)
		if hmac.Equal(got, rawWant) {
			result.reason = "token used raw nonce bytes; daemon expects ascii nonce hex"
		}
	}
	return result
}

func hmacSHA256Hex(secret []byte, msg []byte) string {
	m := hmac.New(sha256.New, secret)
	_, _ = m.Write(msg)
	return hex.EncodeToString(m.Sum(nil))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func readUSBIDs(dev string) (vid, pid string) {
	base := filepath.Base(dev)
	dir := filepath.Join("/sys/class/tty", base, "device")
	for i := 0; i < 8; i++ {
		if b, err := os.ReadFile(filepath.Join(dir, "idVendor")); err == nil {
			vid = strings.TrimSpace(string(b))
		}
		if b, err := os.ReadFile(filepath.Join(dir, "idProduct")); err == nil {
			pid = strings.TrimSpace(string(b))
		}
		if vid != "" || pid != "" {
			return vid, pid
		}
		next := filepath.Dir(dir)
		if next == dir || next == "." || next == "/" {
			break
		}
		dir = next
	}
	return "", ""
}
