package locker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Locker interface {
	Lock(ctx context.Context) error
	Unlock(ctx context.Context) error
	Active(ctx context.Context) (bool, error)
}

type DryRun struct {
	Inner Locker
}

func (d DryRun) Lock(ctx context.Context) error {
	fmt.Println("dry-run: would lock session")
	return nil
}

func (d DryRun) Unlock(ctx context.Context) error {
	fmt.Println("dry-run: would request session unlock")
	return nil
}

func (d DryRun) Active(ctx context.Context) (bool, error) {
	if d.Inner == nil {
		return false, nil
	}
	return d.Inner.Active(ctx)
}

func New(backend string, dryRun bool) (Locker, error) {
	var l Locker
	switch backend {
	case "kde":
		l = KDE{}
	case "logind":
		l = Logind{}
	case "kde-logind":
		l = Hybrid{LockBackend: KDE{}, UnlockBackend: Logind{}}
	default:
		return nil, fmt.Errorf("unknown locker backend %q", backend)
	}
	if dryRun {
		return DryRun{Inner: l}, nil
	}
	return l, nil
}

// KDE talks to Plasma's kscreenlocker through the qdbus6/qdbus command if present,
// with dbus-send as a fallback. This keeps the scaffold Go-stdlib-only.
type KDE struct{}

func (KDE) Lock(ctx context.Context) error {
	if path, err := exec.LookPath("qdbus6"); err == nil {
		return runPath(ctx, path, "org.freedesktop.ScreenSaver", "/ScreenSaver", "org.freedesktop.ScreenSaver.Lock")
	}
	if path, err := exec.LookPath("qdbus"); err == nil {
		return runPath(ctx, path, "org.freedesktop.ScreenSaver", "/ScreenSaver", "org.freedesktop.ScreenSaver.Lock")
	}
	return run(ctx, "dbus-send", "--session", "--dest=org.freedesktop.ScreenSaver", "--type=method_call", "/ScreenSaver", "org.freedesktop.ScreenSaver.Lock")
}

func (KDE) Unlock(context.Context) error {
	// KDE intentionally does not provide a dependable public “unlock without credentials” API
	// on the org.freedesktop.ScreenSaver surface. Use the logind backend if you want to
	// request unlock and your desktop honors logind's Unlock signal.
	return errors.New("kde backend does not implement unlock; use backend=logind or kde-logind")
}

func (KDE) Active(ctx context.Context) (bool, error) {
	var out []byte
	var err error
	if path, lookErr := exec.LookPath("qdbus6"); lookErr == nil {
		out, err = exec.CommandContext(ctx, path, "org.freedesktop.ScreenSaver", "/ScreenSaver", "org.freedesktop.ScreenSaver.GetActive").Output()
	} else if path, lookErr := exec.LookPath("qdbus"); lookErr == nil {
		out, err = exec.CommandContext(ctx, path, "org.freedesktop.ScreenSaver", "/ScreenSaver", "org.freedesktop.ScreenSaver.GetActive").Output()
	} else {
		return false, errors.New("qdbus6/qdbus not found; cannot query KDE active state")
	}
	if err != nil {
		return false, fmt.Errorf("kde GetActive failed: %w", err)
	}
	return strings.TrimSpace(string(out)) == "true", nil
}

// Logind shells out to loginctl. That keeps policy handling in loginctl/logind.
type Logind struct{}

func (Logind) Lock(ctx context.Context) error {
	args := []string{"lock-session"}
	if sid := os.Getenv("XDG_SESSION_ID"); sid != "" {
		args = append(args, sid)
	}
	return run(ctx, "loginctl", args...)
}

func (Logind) Unlock(ctx context.Context) error {
	args := []string{"unlock-session"}
	if sid := os.Getenv("XDG_SESSION_ID"); sid != "" {
		args = append(args, sid)
	}
	return run(ctx, "loginctl", args...)
}

func (Logind) Active(ctx context.Context) (bool, error) {
	sid := os.Getenv("XDG_SESSION_ID")
	if sid == "" {
		return false, errors.New("XDG_SESSION_ID is empty; cannot query logind session")
	}
	cmd := exec.CommandContext(ctx, "loginctl", "show-session", sid, "-p", "LockedHint", "--value")
	out, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("loginctl show-session LockedHint: %w", err)
	}
	return strings.TrimSpace(string(out)) == "yes", nil
}

type Hybrid struct {
	LockBackend   Locker
	UnlockBackend Locker
}

func (h Hybrid) Lock(ctx context.Context) error {
	return h.LockBackend.Lock(ctx)
}

func (h Hybrid) Unlock(ctx context.Context) error {
	return h.UnlockBackend.Unlock(ctx)
}

func (h Hybrid) Active(ctx context.Context) (bool, error) {
	active, err := h.LockBackend.Active(ctx)
	if err == nil {
		return active, nil
	}
	return h.UnlockBackend.Active(ctx)
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v failed: %w: %s", name, args, err, string(out))
	}
	return nil
}

func runPath(ctx context.Context, path string, args ...string) error {
	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v failed: %w: %s", path, args, err, string(out))
	}
	return nil
}
