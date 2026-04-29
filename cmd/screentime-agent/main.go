package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tdeshazo/kde-serial-keylock/internal/locker"
	"github.com/tdeshazo/kde-serial-keylock/internal/screentime"
)

func main() {
	var (
		coordinator  = flag.String("coordinator", "http://127.0.0.1:8787", "screen-time coordinator base URL")
		deviceID     = flag.String("device", hostnameDefault(), "device ID reported to coordinator")
		deviceName   = flag.String("device-name", hostnameDefault(), "friendly device name reported to coordinator")
		userID       = flag.String("user", "", "user ID whose allowance applies to this device")
		backend      = flag.String("backend", "kde-logind", "locker backend: kde, logind, or kde-logind")
		dryRun       = flag.Bool("dry-run", true, "log lock requests without changing the session")
		pollInterval = flag.Duration("poll", time.Second, "coordinator poll/report interval")
		timeout      = flag.Duration("timeout", 1500*time.Millisecond, "HTTP and locker operation timeout")
		offlineGrace = flag.Duration("offline-grace", 30*time.Second, "how long to tolerate coordinator failures before locking")
		debug        = flag.Bool("debug", false, "enable debug logging")
	)
	flag.Parse()
	configureLogging(*debug)

	if *userID == "" {
		slog.Error("user is required", "flag", "-user")
		os.Exit(1)
	}

	l, err := locker.New(*backend, *dryRun)
	if err != nil {
		slog.Error("locker init failed", "backend", *backend, "err", err)
		os.Exit(1)
	}

	client := screentime.Client{
		BaseURL: *coordinator,
		HTTP:    &http.Client{Timeout: *timeout},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("screen-time agent started", "coordinator", *coordinator, "device", *deviceID, "user", *userID, "backend", *backend, "dry_run", *dryRun, "poll", *pollInterval)
	run(ctx, client, l, *deviceID, *deviceName, *userID, *pollInterval, *timeout, *offlineGrace, *dryRun)
	slog.Info("screen-time agent stopped")
}

func run(ctx context.Context, client screentime.Client, l locker.Locker, deviceID, deviceName, userID string, pollInterval, timeout, offlineGrace time.Duration, dryRun bool) {
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var lastCoordinatorOK time.Time
	lockRequested := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		opCtx, cancel := context.WithTimeout(ctx, timeout)
		locked, lockStateErr := l.Active(opCtx)
		cancel()
		if lockStateErr != nil {
			slog.Warn("lock state query failed", "err", lockStateErr)
			locked = true
		}

		opCtx, cancel = context.WithTimeout(ctx, timeout)
		status, err := client.ReportDevice(opCtx, deviceID, deviceName, userID, locked)
		cancel()
		if err != nil {
			slog.Warn("coordinator report failed", "err", err)
			if !lastCoordinatorOK.IsZero() && time.Since(lastCoordinatorOK) < offlineGrace {
				continue
			}
			if lastCoordinatorOK.IsZero() || offlineGrace <= 0 || time.Since(lastCoordinatorOK) >= offlineGrace {
				requestLock(ctx, l, timeout, dryRun, "coordinator offline beyond grace", &lockRequested)
			}
			continue
		}
		lastCoordinatorOK = time.Now()
		lockRequested = false

		slog.Debug("coordinator policy received", "user", status.UserID, "state", status.State, "remaining_seconds", status.RemainingSeconds, "should_lock", status.ShouldLock, "active_devices", status.ActiveDevices)
		if status.ShouldLock {
			requestLock(ctx, l, timeout, dryRun, "allowance expired", &lockRequested)
		}
	}
}

func requestLock(ctx context.Context, l locker.Locker, timeout time.Duration, dryRun bool, reason string, alreadyRequested *bool) {
	if alreadyRequested != nil && *alreadyRequested {
		return
	}
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := l.Lock(opCtx); err != nil {
		slog.Error("session lock request failed", "reason", reason, "err", err)
		return
	}
	if alreadyRequested != nil {
		*alreadyRequested = true
	}
	slog.Info("session lock requested", "reason", reason, "dry_run", dryRun)
}

func hostnameDefault() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "device"
	}
	return h
}

func configureLogging(debug bool) {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}
