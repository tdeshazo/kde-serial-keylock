package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tdeshazo/kde-serial-keylock/internal/config"
	"github.com/tdeshazo/kde-serial-keylock/internal/locker"
	"github.com/tdeshazo/kde-serial-keylock/internal/token"
)

func main() {
	var (
		configPath = flag.String("config", "config.json", "path to JSON config")
		listPorts  = flag.Bool("list-ports", false, "list detected serial ports and exit")
		once       = flag.Bool("once", false, "check once: unlock if token authenticates, otherwise lock")
		authDebug  = flag.Bool("auth-debug", false, "log serial challenge/response diagnostics")
		tokenDiag  = flag.Bool("token-diag", false, "ask token to report key hash and HMAC test vector")
	)
	flag.Parse()

	configureLogging(*authDebug)

	if *listPorts {
		ports, err := token.ListPorts()
		if err != nil {
			exitError(1, "list serial ports failed", "err", err)
		}
		if len(ports) == 0 {
			fmt.Println("no /dev/ttyACM*, /dev/ttyUSB*, or /dev/serial/by-id/* ports found")
			return
		}
		for _, p := range ports {
			if p.Symlink != "" {
				fmt.Printf("%s -> %s", p.Symlink, p.Name)
			} else {
				fmt.Print(p.Name)
			}
			if p.VID != "" || p.PID != "" {
				fmt.Printf(" vid=%s pid=%s", p.VID, p.PID)
			}
			fmt.Println()
		}
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		exitError(1, "config load failed", "path", *configPath, "err", err)
	}

	secret := os.Getenv(cfg.Auth.SecretEnv)
	if secret == "" {
		exitError(1, "secret env is empty", "env", cfg.Auth.SecretEnv)
	}
	logDaemonHash()

	l, err := locker.New(cfg.Locker.Backend, cfg.Locker.DryRun)
	if err != nil {
		exitError(1, "locker init failed", "backend", cfg.Locker.Backend, "err", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	auth := token.Authenticator{
		Cfg: token.Config{
			Port:    cfg.Serial.Port,
			Baud:    cfg.Serial.Baud,
			VID:     cfg.Serial.VID,
			PID:     cfg.Serial.PID,
			Timeout: cfg.ChallengeTimeout(),
			Debug:   *authDebug,
		},
		Secret: []byte(secret),
		TimerWarningHandler: func(warning token.TimerWarning) {
			go notifyTimerWarning(ctx, warning)
		},
	}
	if *authDebug {
		slog.Warn("auth debug enabled", "sensitive", true, "detail", "challenge nonces and per-challenge HMACs will be logged")
	}

	if *tokenDiag {
		checkTokenDiagnostic(ctx, auth)
		return
	}

	if *once {
		checkOnce(ctx, auth, l, cfg.Locker.UnlockWhenAuthenticated, cfg.Locker.DryRun)
		return
	}

	runDaemon(ctx, auth, l, cfg)
}

func configureLogging(debug bool) {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

func exitError(code int, msg string, attrs ...any) {
	slog.Error(msg, attrs...)
	os.Exit(code)
}

func logDaemonHash() {
	exe, err := os.Executable()
	if err != nil {
		slog.Debug("daemon hash unavailable", "step", "executable_path", "err", err)
		return
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		slog.Debug("daemon hash unavailable", "step", "read_executable", "path", exe, "err", err)
		return
	}
	daemonHash := sha256.Sum256(b)
	slog.Info("daemon hash calculated", "path", exe, "sha256", hex.EncodeToString(daemonHash[:]))
}

func checkTokenDiagnostic(ctx context.Context, auth token.Authenticator) {
	diag, err := auth.Diagnose(ctx)
	attrs := []any{
		"port", diag.Port,
		"host_key_sha256", diag.ExpectedKeyHash,
		"token_key_sha256", diag.KeyHash,
		"key_hash_match", diag.KeyHashMatches(),
		"message", "KEYLOCK-TEST-NONCE",
		"host_test_hmac", diag.ExpectedTestMAC,
		"token_test_hmac", diag.TestMAC,
		"test_hmac_match", diag.TestMACMatches(),
	}
	if err != nil {
		attrs = append(attrs, "err", err, "raw_lines", diag.RawLines)
		slog.Error("token diagnostic failed", attrs...)
		os.Exit(2)
	}
	if !diag.KeyHashMatches() || !diag.TestMACMatches() {
		slog.Error("token diagnostic mismatch", attrs...)
		os.Exit(2)
	}
	slog.Info("token diagnostic matched", attrs...)
}

func notifyTimerWarning(ctx context.Context, warning token.TimerWarning) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		"notify-send",
		"--app-name=Session Monitor",
		"--icon=dialog-information",
		"--urgency=normal",
		"--expire-time=5000",
		"KDE session state",
		"Session locking in 5 minutes!",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() == context.Canceled {
			return
		}
		attrs := []any{"port", warning.Port, "remaining_seconds", warning.Remaining, "err", err}
		if output := strings.TrimSpace(string(out)); output != "" {
			attrs = append(attrs, "output", output)
		}
		slog.Warn("timer warning notification failed", attrs...)
		return
	}
	slog.Info("timer warning notification sent", "port", warning.Port, "remaining_seconds", warning.Remaining)
}

func checkOnce(ctx context.Context, auth token.Authenticator, l locker.Locker, unlock bool, dryRun bool) {
	port, err := auth.Authenticate(ctx)
	if err == nil {
		slog.Info("token authenticated", "port", port)
		if unlock {
			if err := l.Unlock(ctx); err != nil {
				slog.Warn("unlock request failed", "err", err)
			} else {
				slog.Info("session unlock requested", "dry_run", dryRun)
			}
		}
		return
	}
	slog.Warn("token absent or invalid", "err", err)
	if err := l.Lock(ctx); err != nil {
		slog.Error("lock request failed", "err", err)
	} else {
		slog.Info("session lock requested", "dry_run", dryRun)
	}
	os.Exit(2)
}

func runDaemon(ctx context.Context, auth token.Authenticator, l locker.Locker, cfg config.Config) {
	const retryLogThreshold = 3

	slog.Info(
		"keylock started",
		"backend", cfg.Locker.Backend,
		"dry_run", cfg.Locker.DryRun,
		"poll_interval", cfg.PollInterval(),
		"relock_interval", cfg.RelockInterval(),
		"unlock_when_authenticated", cfg.Locker.UnlockWhenAuthenticated,
	)
	defer pauseTimerOnStop(auth)

	authenticated := false
	lastLock := time.Time{}
	var timerLockState *bool
	lockStateErrs := 0
	lockStateErrLogged := false
	var timerEventErrState *bool
	timerEventErrs := 0
	timerEventErrLogged := false
	lockRequestErrs := 0
	lockRequestErrLogged := false
	lockRequestLogged := false
	poll := cfg.PollInterval()
	if poll <= 0 {
		poll = time.Second
	}

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("keylock stopping", "err", ctx.Err())
			return
		case <-ticker.C:
		}

		if active, err := l.Active(ctx); err != nil {
			lockStateErrs++
			if lockStateErrs >= retryLogThreshold && !lockStateErrLogged {
				slog.Warn("lock state query failing", "attempts", lockStateErrs, "err", err)
				lockStateErrLogged = true
			}
		} else {
			if lockStateErrLogged {
				slog.Info("lock state query recovered", "attempts", lockStateErrs)
			}
			lockStateErrs = 0
			lockStateErrLogged = false
			if timerLockState == nil || *timerLockState != active {
				status, err := auth.SendTimerLockState(ctx, active)
				if err != nil {
					if timerEventErrState == nil || *timerEventErrState != active {
						timerEventErrState = boolPtr(active)
						timerEventErrs = 0
						timerEventErrLogged = false
					}
					timerEventErrs++
					if timerEventErrs >= retryLogThreshold && !timerEventErrLogged {
						slog.Warn("timer lock-state event failing", "event", lockStateName(active), "attempts", timerEventErrs, "err", err)
						timerEventErrLogged = true
					}
				} else {
					recovered := timerEventErrLogged
					attempts := timerEventErrs
					timerLockState = boolPtr(active)
					timerEventErrState = nil
					timerEventErrs = 0
					timerEventErrLogged = false
					attrs := []any{
						"event", lockStateName(active),
						"port", status.Port,
						"timer_state", status.State,
						"remaining_seconds", status.Remaining,
					}
					if recovered {
						attrs = append(attrs, "recovered", true, "attempts", attempts)
					}
					slog.Info("timer lock-state event sent", attrs...)
				}
			}
		}

		port, err := auth.Authenticate(ctx)
		if err == nil {
			if !authenticated {
				slog.Info("token authenticated", "port", port)
				if cfg.Locker.UnlockWhenAuthenticated {
					if err := l.Unlock(ctx); err != nil {
						slog.Warn("unlock request failed", "err", err)
					} else {
						slog.Info("session unlock requested", "dry_run", cfg.Locker.DryRun)
					}
				}
			}
			authenticated = true
			lockRequestErrs = 0
			lockRequestErrLogged = false
			lockRequestLogged = false
			continue
		}

		if authenticated {
			slog.Warn("token lost or failed authentication", "err", err)
		}
		authenticated = false

		if time.Since(lastLock) >= cfg.RelockInterval() {
			if err := l.Lock(ctx); err != nil {
				lockRequestErrs++
				if lockRequestErrs >= retryLogThreshold && !lockRequestErrLogged {
					slog.Error("session lock request failing", "attempts", lockRequestErrs, "err", err)
					lockRequestErrLogged = true
				}
			} else {
				if lockRequestErrLogged {
					slog.Info("session lock request recovered", "attempts", lockRequestErrs, "dry_run", cfg.Locker.DryRun)
					lockRequestLogged = true
				} else if !lockRequestLogged {
					slog.Info("session lock requested", "dry_run", cfg.Locker.DryRun)
					lockRequestLogged = true
				}
				lastLock = time.Now()
				lockRequestErrs = 0
				lockRequestErrLogged = false
			}
		}
	}
}

func pauseTimerOnStop(auth token.Authenticator) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	status, err := auth.PauseTimer(ctx)
	if err != nil {
		slog.Warn("timer pause event failed during shutdown", "err", err)
		return
	}
	slog.Info("timer pause event sent during shutdown", "port", status.Port, "timer_state", status.State, "remaining_seconds", status.Remaining)
}

func boolPtr(v bool) *bool {
	return &v
}

func lockStateName(locked bool) string {
	if locked {
		return "LOCKED"
	}
	return "UNLOCKED"
}
